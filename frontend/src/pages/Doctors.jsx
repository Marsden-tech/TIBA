import React, { useContext } from 'react'
import { useParams } from 'react-router-dom'
import { AppContext } from '../context/AppContext'

const Doctors = () => {

  const {speciality} = useParams()

  const {doctors} = useContext(AppContext)

  return (
    <div>
        <p>Search from our specialist doctors</p>
    </div>
  )
}

export default Doctors