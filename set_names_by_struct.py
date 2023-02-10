import idaapi

def set_list_of_objects_names(start, name_format, num_of_elemens, struct, obj_field, objAlign, name_field):
    #print(start, struct, obj_field, name_field, num_of_elemens)
    size_of_element = idaapi.get_struc_size(struct[1])
    obj_offset = idaapi.get_member_by_name(idaapi.get_struc(struct[1]), obj_field).soff
    name_offset = idaapi.get_member_by_name(idaapi.get_struc(struct[1]), name_field).soff
    name_string_or_pointer = False
    if(idaapi.is_strlit(idaapi.get_member_by_name(idaapi.get_struc(struct[1]), name_field).flag)):
        name_string_or_pointer = True
    
    for i in range(start, start+num_of_elemens*size_of_element, size_of_element):
        obj_addr = idaapi.get_dword(i+obj_offset)
        obj_addr = obj_addr & ~(objAlign - 1)
        if(obj_addr == 0):
            continue
        if(name_string_or_pointer): #string
            name = idaapi.get_strlit_contents(i+name_offset, -1,0,0)
        else:
            name = idaapi.get_strlit_contents(idaapi.get_dword(i+name_offset), -1,0,0)
        try:
            name = name.decode()
            #print("addr %08x: name %s" % (obj_addr, name_format%name))
            if(obj_addr and len(name) >= 2):
                idaapi.set_name(obj_addr, name_format%name)
        except:
            print("could not decode name")
            break



class IdaNameFromStructForm(idaapi.Form):
    """ Ida apply names from structs form """

    def __init__(self, select_list = None):
        self.select_list = select_list
        self.segments = [0,1]
        self.ok = False
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
            if(idaapi.get_member_by_name(idaapi.get_struc(ti.tid), "obj")):
                self.obj_idx = list(map(lambda s:s[1] == "obj", StructMembers(ti.tid))).index(True)
         
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
<Object field       :{objFieldChooser}>
<namn field         :{nameFieldChooser}>
Object Alignment     <Byte :{rByte}><Word :{rWord}><Dword :{rDWord}>{objAlign}>
""", {
                'address'   : idaapi.Form.NumericInput(),
                'nameFormat'   : idaapi.Form.StringInput(),
                'numOfElems'   : idaapi.Form.NumericInput(),
                'structChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.current_struct_list_idx),
                'objFieldChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.obj_idx),
                'nameFieldChooser'   : idaapi.Form.DropdownListControl(readonly=True, selval=self.name_idx),
                'objAlign' : idaapi.Form.RadGroupControl(("rByte", "rWord", "rDWord")),
                'FormChangeCb'    : idaapi.Form.FormChangeCb(self.OnFormChange),
            })
        
        self.Compile()
        
        #initialize controls default values
        self.structChooser.set_items(['{:<50}'.format(s[2]) for s in self.struct_list])
        
        sid = self.struct_list[self.current_struct_list_idx][1]
        self.field_list = [f for f in StructMembers(sid)]
        fields = ['{:<50}'.format(f[1]) for f in self.field_list]
        self.objFieldChooser.set_items(fields) 
        self.nameFieldChooser.set_items(fields) 
        
        self.address.value = here()
        self.nameFormat.value = "%s"

    def OnFormChange(self, fid):
        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.nameFormat)
        elif(fid == self.structChooser.id):
            
            idx = self.GetControlValue(self.structChooser)
            sid = self.struct_list[idx][1]
            #load new struct fileds
            self.field_list = [f for f in StructMembers(sid)]
            fields = ['{:<50}'.format(f[1]) for f in self.field_list]
            self.objFieldChooser.set_items(fields) 
            self.nameFieldChooser.set_items(fields)
            self.RefreshField(self.objFieldChooser)
            self.RefreshField(self.nameFieldChooser)
        # Form OK pressed
        elif fid == -2:
            self.ok = True
        return 1

alignment = [1,2,4]
a = IdaNameFromStructForm()
a.Execute()
if(a.ok):
    set_list_of_objects_names(a.address.value,
                        a.nameFormat.value,
                        a.numOfElems.value,
                        a.struct_list[a.structChooser.value],
                        a.field_list[a.objFieldChooser.value][1],
                        alignment[a.objAlign.value],
                        a.field_list[a.nameFieldChooser.value][1],
                        )
a.Free()
