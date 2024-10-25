import axios from "axios";
import { createContext, useState } from "react";
import { toast } from "react-toastify";


export const AdminContext = createContext()

const AdminContextProvider = (props) => {

    const [aToken, setAToken] = useState(localStorage.getItem('aToken') ? localStorage.getItem('aToken') : '')
    const [doctors, setDoctors] = useState([])
    const [appointments, setAppointments] = useState([])
    const [dashData, setDashData] = useState(false)

    const backendUrl = import.meta.env.VITE_BACKEND_URL

    const getAllDoctors = async () => {
        try {

            const { data } = await axios.post(backendUrl + '/admin-doctors', {}, { headers: { 'Authorization': aToken } })
            if (data.success) {
                setDoctors(data.doctors)
            } else {
                toast.error(data.message)
            }

        } catch (error) {
            toast.error(error.message)
        }
    }

    const changeAvailability = async (docId) => {

        try {

            const { data } = await axios.patch(backendUrl + `/admin-update-doctor-availability/${docId}`, {}, { headers: { 'Authorization': aToken } })

            if (data.success) {
                toast.success(data.message)
                getAllDoctors()
            } else {
                toast.error(data.message)
            }

        } catch (error) {

            toast.error(error.message)

        }

    }

    const getAllAppointments = async () => {

        try {

            const { data } = await axios.get(backendUrl + '/admin-appointments', { headers: { 'Authorization': aToken } })

            if (data.success) {
                setAppointments(data.appointments)
            } else {
                toast.error(data.message)
            }

        } catch (error) {
            toast.error(error.message)
        }

    }

    const cancelAppointment = async (appointmentId) => {
        try {

            const {data} = await axios.post(backendUrl+'/admin/cancel-appointment',{appointmentId}, { headers: { 'Authorization': aToken } })

            if (data.success) {
                toast.success(data.message)
                getAllAppointments()
            } else {
                toast.error(data.message)
            }

            
        } catch (error) {
            
        }
    }
    
    const getDashData = async () => {
        try {

            const {data} = await axios.get(backendUrl+'/admin-dashboard', { headers: { 'Authorization': aToken } })
            if (data.success) {
                setDashData(data.dashData)
            } else {
                toast.error(data.message)
            }
            
        } catch (error) {
            toast.error(data.message)
        }
    }

    const value = {
        aToken, setAToken,
        backendUrl, doctors,
        getAllDoctors, changeAvailability,
        appointments, setAppointments,
        getAllAppointments,
        cancelAppointment,
        dashData, getDashData
    }

    return (
        <AdminContext.Provider value={value}>
            {props.children}
        </AdminContext.Provider>
    )
}

export default AdminContextProvider
