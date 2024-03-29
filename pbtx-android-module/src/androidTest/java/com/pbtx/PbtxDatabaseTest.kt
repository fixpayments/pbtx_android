package com.pbtx


import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.pbtx.utils.PbtxUtils
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import pbtx.KeyWeight
import pbtx.Permission
import java.util.concurrent.ThreadLocalRandom

@RunWith(AndroidJUnit4::class)
class PbtxDatabaseTest {

    @Test
    fun useAppContextTest() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val pbtxClient = PbtxClient(context)
        Assert.assertNotNull(pbtxClient)
    }

    @Test
    fun registrationFlowTest() = runBlocking {
        val networkId = 100L
        val actor = ThreadLocalRandom.current().nextLong()
        var seqNum = 0
        var prevHash = 0L
        val context = ApplicationProvider.getApplicationContext<Context>()
        val pbtxClient = PbtxClient(context)

        //init registration
        val registrationKey = pbtxClient.initLocalRegistration()

        //creating Permission object
        val permission = PbtxUtils.buildBasicPermissionForActor(actor, registrationKey.publicKey)

        //register account with default
        pbtxClient.registerLocalAccount(networkId, permission, seqNum, prevHash)
        var localSyncHead = pbtxClient.getLocalSyncHead(networkId, actor)
        Assert.assertEquals(seqNum, localSyncHead.first)
        Assert.assertEquals(prevHash, localSyncHead.second)

        //update account seqNum + prevHash
        seqNum = 10
        prevHash = 120120L
        pbtxClient.updateLocalSyncHead(networkId, actor, seqNum, prevHash)
        localSyncHead = pbtxClient.getLocalSyncHead(networkId, actor)
        Assert.assertEquals(seqNum, localSyncHead.first)
        Assert.assertEquals(prevHash, localSyncHead.second)


        //try to register same account again
        try {
            pbtxClient.registerLocalAccount(networkId, permission, seqNum, prevHash)
            Assert.fail("Registration was already completed once")
        } catch (e: Exception) {
            Assert.assertTrue(e.message!!.startsWith("The registration process was already completed"))
        }

    }
}