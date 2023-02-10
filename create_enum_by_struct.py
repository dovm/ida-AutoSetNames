import idaapi


def get_enum_list():
    num_of_enums = get_enum_qty()
    enums = []
    for i in range(num_of_enums):
        enums.append([getn_enum(i), get_enum_name(getn_enum(i))])
    return enums

def create_enum(is_enum_exist, enum_name, exist_enum_name):
    if(is_enum_exist):
        return get_enum(exist_enum_name)
    else:
        add_enum(0xffffffff, enum_name, idaapi.hex_flag())
        return get_enum(enum_name)



def add_members_to_enum(enum_id, start, name_format, num_of_elemens, struct, id_field, name_field):
    #print(start, struct, obj_field, name_field, num_of_elemens)
    size_of_element = idaapi.get_struc_size(struct[1])
    id_offset = idaapi.get_member_by_name(idaapi.get_struc(struct[1]), id_field).soff
    name_offset = idaapi.get_member_by_name(idaapi.get_struc(struct[1]), name_field).soff
    name_string_or_pointer = False
    if(idaapi.is_strlit(idaapi.get_member_by_name(idaapi.get_struc(struct[1]), name_field).flag)):
        name_string_or_pointer = True
    
    for i in range(start, start+num_of_elemens*size_of_element, size_of_element):
        enum_member_id = idaapi.get_dword(i+id_offset)
        
        if(name_string_or_pointer): #string
            name = idaapi.get_strlit_contents(i+name_offset, -1,0,0)
        else:
            name = idaapi.get_strlit_contents(idaapi.get_dword(i+name_offset), -1,0,0)
        try:
            print("addr %08x: name %s" % (enum_member_id, name_format%name))
            name = name.decode()
            if(enum_member_id and len(name) >= 2):
                idaapi.add_enum_member(enum_id, name_format%name, enum_member_id, 0xFFFFFFFF)
        except:
            print("could not decode name")
            break



class IdaNameFromStructForm(idaapi.Form):
    """ Ida apply names from structs form """

    def __init__(self, select_list = None):
        self.select_list = select_list
        self.segments = [0,1]
        self.ok = False
        self.enum_list = get_enum_list()
        self.struct_list = [s for s in Structs()]
        ea = here()
        ti = idaapi.opinfo_t()
        f = idaapi.get_flags(ea)
        if idaapi.get_opinfo(ti, ea, 0, f):
            self.current_struct_list_name = idaapi.get_struc_name(ti.tid)
            self.current_struct_list_idx = list(map(lambda s:s[2] == self.current_struct_list_name, self.struct_list)).index(True)
            self.name_idx = 0
            if(idaapi.get_member_by_name(idaapi.get_struc(ti.tid), "name")):
                self.name_idx = list(map(lambda s:s[1] == "name", StructMembers(ti.tid))).index(True)
            
            self.obj_idx=0
            if(idaapi.get_member_by_name(idaapi.get_struc(ti.tid), "id")):
                self.obj_idx = list(map(lambda s:s[1] == "id", StructMembers(ti.tid))).index(True) 
        else:
            self.current_struct_list_idx = 0
        idaapi.Form.__init__(self, 
r"""BUTTON YES* Set Names
Apply name from struct     
{FormChangeCb}
<Address            :{address}>
<Name format        :{nameFormat}>
<Number of elements :{numOfElems}>
<Struct type        :{structChooser}>
<ID field           :{idFieldChooser}>
<name field         :{nameFieldChooser}>
<Existing Enum      :{rIsExistEnum}>{existEnum}>
<Enum Name          :{enumName}>
<Enum List          :{enumList}>
""", {
                'address'   : idaapi.Form.NumericInput(),
                'nameFormat'   : idaapi.Form.StringInput(),
                'numOfElems'   : idaapi.Form.NumericInput(),
                'structChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.current_struct_list_idx),
                'idFieldChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.obj_idx),
                'nameFieldChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.name_idx),
                'existEnum' : idaapi.Form.ChkGroupControl(("rIsExistEnum",)),
                'enumName'   : idaapi.Form.StringInput(),
                'enumList'   : idaapi.Form.DropdownListControl(readonly=True),
                'FormChangeCb'    : idaapi.Form.FormChangeCb(self.OnFormChange),
            })
        
        print(self.Compile()[1][0].decode())
        
        #initialize controls default values
        self.structChooser.set_items(['{:<50}'.format(s[2]) for s in self.struct_list])
        
        sid = self.struct_list[self.current_struct_list_idx][1]
        self.field_list = [f for f in StructMembers(sid)]
        fields = ['{:<50}'.format(f[1]) for f in self.field_list]
        self.idFieldChooser.set_items(fields) 
        self.nameFieldChooser.set_items(fields) 
        self.enumList.set_items([e[1] for e in self.enum_list])

        self.address.value = here()
        self.nameFormat.value = "%s"

        self.existEnum.value = 0

    def OnFormChange(self, fid):
        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.nameFormat)
            self.EnableField(self.enumList, False)
        elif(fid == self.existEnum.id):
            enum_exist = self.GetControlValue(self.existEnum)
            self.EnableField(self.enumList, enum_exist)
            self.EnableField(self.enumName, not enum_exist)
        elif(fid == self.structChooser.id):
            
            idx = self.GetControlValue(self.structChooser)
            sid = self.struct_list[idx][1]
            #load new struct fileds
            self.field_list = [f for f in StructMembers(sid)]
            fields = ['{:<50}'.format(f[1]) for f in self.field_list]
            self.idFieldChooser.set_items(fields) 
            self.nameFieldChooser.set_items(fields)
            self.RefreshField(self.idFieldChooser)
            self.RefreshField(self.nameFieldChooser)
        # Form OK pressed
        elif fid == -2:
            self.ok = True
        return 1

alignment = [1,2,4]
a = IdaNameFromStructForm()
a.Execute()
if(a.ok):
    enum_id = create_enum(a.existEnum.value,
                       a.enumName.value,
                       a.enum_list[a.enumList.value][1]
                       )
    add_members_to_enum(enum_id,
                        a.address.value,
                        a.nameFormat.value,
                        a.numOfElems.value,
                        a.struct_list[a.structChooser.value],
                        a.field_list[a.idFieldChooser.value][1],
                        a.field_list[a.nameFieldChooser.value][1],
                        )
a.Free()
