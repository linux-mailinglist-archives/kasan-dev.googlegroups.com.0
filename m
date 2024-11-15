Return-Path: <kasan-dev+bncBDWIXJOWRAFRBQ7I3W4QMGQE25NB6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 41FDB9CF137
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 17:18:18 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6cbd2cb2f78sf33952556d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 08:18:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731687492; cv=pass;
        d=google.com; s=arc-20240605;
        b=liIP8FfPVNSFA5rdYku4vHLWy6XWspfEWYTUgatdt3W5K16bb6hCoes6Z0ctqStGdc
         QR46ZjhD8ZK+wjK8U2Ot8MDp4Ck8Gxiei1P3/r+lxo3LCl7EQ2VDQO4zRyZnEhaV6fcZ
         BFOQeuJ0PdlRSqjFvgJJ6ukL8pDW/1bT6Ur3jSx3Q3qsIvNOp23UwU8dP5rpkNGl0cQ0
         1cycrLRTddp8TwaAQ/juxoBv+79CTCtz5LwOKj19XPua9MVTFh4PiS34H2lR8axGM2vW
         3f0GSTFE+5cN61Y02mVi12s8eNI9GYPcn16Zs11qI+9wzp7RoUFgNlqKetOK7T/HLon2
         Rpng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=f9hLAgsC/5iGJPSvYjJ7NJCgGAR9Ow1IrBrVunnANQU=;
        fh=Au7Kjx/VYN7T19fcE1grkmOk0hNRi+/615LKJIUTH6Q=;
        b=bq85kJL72BJSK7xSjxuWsgLyo7YyWfFg+aHGSlQL1oQYrFqyJoOgdY9irnQiwnQsgx
         a2a27TR/ikxz34a2aCjs4U0W8lL0Wiqgzrhs7Iz7g9wS64cVAgZ+3oXivpsANs5d1YVY
         ZvFVoPXumR7nHp69g4MdrHXLY9AePtqp4t9WuxMq7o/7Igog1dNcRFaB0mpe+KW/JpF8
         ZI0BiNGT4k2ZoB2BQEN3oSfxN1WXFxoTpesWZghBlJnRMam39XxrcscWkM11Bx8NxL79
         KacSq87Q3MrUAXZVlU1yf9GBPFSxLUozDHJsBcKbgfLFazA6Ka83yJn4mkwR7YKWX63w
         sq6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V6NYdIcT;
       spf=pass (google.com: domain of munisekharrms@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=munisekharrms@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731687492; x=1732292292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f9hLAgsC/5iGJPSvYjJ7NJCgGAR9Ow1IrBrVunnANQU=;
        b=DR0X6HczE4wYrt9Esa1kC0ao2xJWXgaRUhSf8I+KVuRVOcjbfFRXmKcwVDahSl/8Dt
         u6ll569ar9DvRbzHOYzzBtTfYK+bRejXJTxlyJ47uLt5pC0t6dxrjuIpCSvNW5sgcegd
         Xla4+Ydw22E3mn4SpfgER2CL2YBOAnCE24CCpN/LXaBKbH2Pj7hTkyP4nQ0pQ5EcqG0l
         lFKa+W3J0PoxrPPMHEqbqCn3Wr1ISqaiT1M9+IkCCv+1yDb28CoMt6/JPip7HpdKB0zC
         oUnIJDvtXlppr8vfFvE9Wwg7R0uoDynhIq+UhSEbIFFDCcM4oqYOmeS4EYJLD2hdEeXG
         Gz+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731687492; x=1732292292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=f9hLAgsC/5iGJPSvYjJ7NJCgGAR9Ow1IrBrVunnANQU=;
        b=TW5cs4xZozkI9w9o7+hKyVpFApLsyO3l9VaN4SiFQKiZufYP06yHPb0H1P1vYRL94E
         DGjIfabPq8unPzDSn7mRbT6e+hEIIYeaBA4gFd/IAmke00sVOZEU8Tenm8eTjibhGbG4
         OHnbbaMlHQyZi/r7FScentuJ+8ApTs/dszvH8N8Uih84/YdQameu/OdZ76raOtpRxxP6
         TLCAovysrvS0ck+I/ZbWeMFml37hrPip3Z+YZMpAHOEWhovMLvo6XjwjdGSIXomNr9qD
         JnIDglrcX0Qy1k7tEdfJPlQZ6mYXuauUxFUv0cQv3nKUOnXqX3nYgpyJoB1ltBM5Crqj
         TFEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731687492; x=1732292292;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f9hLAgsC/5iGJPSvYjJ7NJCgGAR9Ow1IrBrVunnANQU=;
        b=OLQT0/uHh219Ekc/KV+a19kQr0EQCrRPqpc1hBGelYLakAUTeX9fSxR87oTWe4Y1lI
         WZz2h+/LRVFzj1QFPPaREpf9IO7o6HKDy+hoMGniK4twx6VV67msjNDo/3MWVSaFBkiC
         g9lN3sZHENklczdf24ns1kAljHWqdPVviL+dB1XwlMAYKnq/z1dyTXbNggjn0TVn3grm
         uzArvIsSBiYu0kPLGxeyY4mb+IYk0nSqPjLGq2/uG7GzFMltQ9M6+TEBRyjnTD9rVObp
         Yka4na9h1ImaVbIo8Dr76ASQeBvFGsG4SfTD0CipFCKuFHorFkX+3VMx2zZVW1QGWNvJ
         4sBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3JKFyPUY3t6WT3PQFjLcHyGd4H2z4WFkxB98rT1hsLJQxTMPcxb63lUgkPtXJrmrnVv/VWA==@lfdr.de
X-Gm-Message-State: AOJu0YxiO3LQ65wtryQYdEkiVA4owa3xU7SjmNUGnKqHDHxmoH7iXpY8
	+RdjSPoDlLSxjH+MjZzeZAUkCKzY63aWQLIPI8SDUDLjJXrjmgr6
X-Google-Smtp-Source: AGHT+IHF9LBan8HJHv2x3y5UjlX8ew9sSd3RDBvCHmyq3QAFoSLm/EAV7buAizGU3gaKo/+KvPblWQ==
X-Received: by 2002:a05:6214:27e8:b0:6d4:b88:492e with SMTP id 6a1803df08f44-6d40b886e48mr3250406d6.17.1731687491738;
        Fri, 15 Nov 2024 08:18:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:258e:b0:6cb:84ef:ca5e with SMTP id
 6a1803df08f44-6d3e99b21c5ls2716596d6.2.-pod-prod-00-us; Fri, 15 Nov 2024
 08:18:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX5Mcdo3qQkCm07suLI5AfVcXXCYm9v9DiFWMR/CiW7kzeNtEwAMeFwsgDCkFSSS0LSp0143qX04RE=@googlegroups.com
X-Received: by 2002:a05:6214:194a:b0:6cb:644e:c9a8 with SMTP id 6a1803df08f44-6d3e8fa908amr130577446d6.4.1731687490929;
        Fri, 15 Nov 2024 08:18:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731687490; cv=none;
        d=google.com; s=arc-20240605;
        b=Zo1UBjaqA0CjyCoVj1q1D85Av71a0KLypRUyMkFaacKBfMN4aodkIFB9jVTK84TKPg
         STqRo9/8auA6kmDeFCa9urPLW1yexhCM2QutCar+bT112/juxLE97g7PsXKcpuSkI1bE
         W+QJVKCn1lst6GG0fRTURMP6t2YNmXjyOhu7I7Z+6vUzKqXUGtt+Gq8VSedZpKdW21pr
         eidMt3VC1O6N24utfthBDmjfOySvbbGUW1x+jZZ6krY4YE0tZSVgwaN+MAzBdLN0TO+k
         R9XjrIkPkhFxbG8+JXTWO7as7H00CoYW4/9nI06h28Qi1IFYww4qK4KAv8wOMpR16utv
         zbQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=VPRAwnJHM0yj/wQYaOzcRH9Aml3wNsDwQd5Odhgyr5E=;
        fh=cRqLB4d1RLan3q149gES7ztmv3K1K9eJp9JRPXUWzxU=;
        b=kIu6G3hZnR1pcMG1XwuHftsxit8GWa3cbtGw5IFxT9V44x+3P4tfJWLj4O9aZLDSdN
         Ed3IRu3/bcozspz9zLyh1xuAbfZy0Y4j4DkktEiKZTSt8QFV7TLO51rjTLKvrGrXyNZk
         YB4iYgkm4L5HaFIPzofkpOg1sB8fRfGg6rTYwasRMvuf1oxGG9ghvqiuHDE+hjtJ9ePP
         LE3yPM1ivHelZSp4HpvuC9De9xFzRwwW02SK2wu/9hDRz4SbRe2C3BR4HJ897xI073pM
         OTwvCswPtWC74SMvzdfLEMNL+yTtm0HvaWJKxQXtdG9KpNt+VEBYPHBbqPwCc3IAitQo
         VCVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V6NYdIcT;
       spf=pass (google.com: domain of munisekharrms@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=munisekharrms@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6d3ee8de52bsi1702386d6.5.2024.11.15.08.18.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2024 08:18:10 -0800 (PST)
Received-SPF: pass (google.com: domain of munisekharrms@gmail.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 006d021491bc7-5ee9dbf1b47so983082eaf.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2024 08:18:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWAbR3faEYjYBCAQCYdV3NYQZegbKpC8AQY1tZsGKJOqE0JbGEQ3GgQ5QdnH1x3IEb188b1vvxnRtE=@googlegroups.com
X-Received: by 2002:a05:6870:1cb:b0:294:cac8:c788 with SMTP id
 586e51a60fabf-29606a062fdmr5454685fac.6.1731687490275; Fri, 15 Nov 2024
 08:18:10 -0800 (PST)
MIME-Version: 1.0
From: Muni Sekhar <munisekharrms@gmail.com>
Date: Fri, 15 Nov 2024 21:47:59 +0530
Message-ID: <CAHhAz+i+4iCn+Ddh1YvuMn1v-PfJj72m6DcjRaY+3vx7wLhFsQ@mail.gmail.com>
Subject: Help Needed: Debugging Memory Corruption results GPF
To: kernel-hardening@lists.openwall.com, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kernelnewbies <kernelnewbies@kernelnewbies.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: munisekharrms@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V6NYdIcT;       spf=pass
 (google.com: domain of munisekharrms@gmail.com designates 2607:f8b0:4864:20::c2b
 as permitted sender) smtp.mailfrom=munisekharrms@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi all,

I am encountering a memory corruption issue in the function
msm_set_laddr() from the Slimbus MSM Controller driver source code.
https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-sunfish-4.14-android12/drivers/slimbus/slim-msm-ctrl.c

In msm_set_laddr(), one of the arguments is ea (enumeration address),
which is a pointer to constant data. While testing, I observed strange
behavior:

The contents of the ea buffer get corrupted during a timeout scenario
in the call to:

timeout = wait_for_completion_timeout(&done, HZ);

Specifically, the ea buffer's contents differ before and after the
wait_for_completion_timeout() call, even though it's declared as a
pointer to constant data (const u8 *ea).
To debug this issue, I enabled KASAN, but it didn't reveal any memory
corruption. After the buffer corruption, random memory allocations in
other parts of the kernel occasionally result in a GPF crash.

Here is the relevant part of the code:

static int msm_set_laddr(struct slim_controller *ctrl, const u8 *ea,
                         u8 elen, u8 laddr)
{
    struct msm_slim_ctrl *dev = slim_get_ctrldata(ctrl);
    struct completion done;
    int timeout, ret, retries = 0;
    u32 *buf;
retry_laddr:
    init_completion(&done);
    mutex_lock(&dev->tx_lock);
    buf = msm_get_msg_buf(dev, 9, &done);
    if (buf == NULL)
        return -ENOMEM;
    buf[0] = SLIM_MSG_ASM_FIRST_WORD(9, SLIM_MSG_MT_CORE,
                                     SLIM_MSG_MC_ASSIGN_LOGICAL_ADDRESS,
                                     SLIM_MSG_DEST_LOGICALADDR,
                                     ea[5] | ea[4] << 8);
    buf[1] = ea[3] | (ea[2] << 8) | (ea[1] << 16) | (ea[0] << 24);
    buf[2] = laddr;
    ret = msm_send_msg_buf(dev, buf, 9, MGR_TX_MSG);
    timeout = wait_for_completion_timeout(&done, HZ);
    if (!timeout)
        dev->err = -ETIMEDOUT;
    if (dev->err) {
        ret = dev->err;
        dev->err = 0;
    }
    mutex_unlock(&dev->tx_lock);
    if (ret) {
        pr_err("set LADDR:0x%x failed:ret:%d, retrying", laddr, ret);
        if (retries < INIT_MX_RETRIES) {
            msm_slim_wait_retry(dev);
            retries++;
            goto retry_laddr;
        } else {
            pr_err("set LADDR failed after retrying:ret:%d", ret);
        }
    }
    return ret;
}

What I've Tried:
KASAN: Enabled it but couldn't identify the source of the corruption.
Debugging Logs: Added logs to print the ea contents before and after
the wait_for_completion_timeout() call. The logs show a mismatch in
the data.

Question:
How can I efficiently trace the source of the memory corruption in
this scenario?
Could wait_for_completion_timeout() or a related function cause
unintended side effects?
Are there additional tools or techniques (e.g., dynamic debugging or
specific kernel config options) that can help identify this
corruption?
Any insights or suggestions would be greatly appreciated!



-- 
Thanks,
Sekhar

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHhAz%2Bi%2B4iCn%2BDdh1YvuMn1v-PfJj72m6DcjRaY%2B3vx7wLhFsQ%40mail.gmail.com.
