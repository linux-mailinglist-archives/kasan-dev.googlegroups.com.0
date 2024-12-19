Return-Path: <kasan-dev+bncBC72VC6I3MMBBJXKSG5QMGQEJ4INFEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E4939F8464
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2024 20:34:00 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5f327bea5b0sf995759eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2024 11:34:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734636839; cv=pass;
        d=google.com; s=arc-20240605;
        b=VWaHyfOaRhbgbBA5WbeSM1/Ao6C+SODE2dRRDSLrrzXHP255XYBYcdXtBt7jMTPGVo
         uA6zwsNx+FLqZyVWWSCfd9hZYCdCjoTZ4cXd+i8BiGENPsFtrzT6Rw6RWO8ywS9pFnMa
         8fVi9aegFAlbR/uuMPac+RjapY6VQNAKcbjmds0GFWWgRsVWPTwh6bq3cGJHtTk3E1cZ
         LutNm5trKWoqObKyiO87FCDZLKoTucJAS6jfBbKxHAkz8qyfyqZDurnPOZ5QGNwTP3qL
         aAcXO0PX7Zla+8EaO+d5ex7ARWrqjbPaE0MEDkCK00knloV0Ojk2Xt0oeaZbWrnh6EWZ
         ZCrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=js51kEbp+GN6LLwgWGp9XmePWQwU5kNxLYvG5BoxL+M=;
        fh=FePETXvL/hzWMlMi2ztJ5Gu6nMxdQpWvp9YiQyhS6NQ=;
        b=MZfRYWAWq6OUCKvciHyZMM/vz44aiGuaeJFXTUG+kegAhtVUJkJVlkWJSlESUtc4fS
         L6pK0Xb9tfwfaMkTStbYhsXJhfcnjVyZxH3JUmrtccUSxEgLycB/NgdoKtPrzd+3mXYd
         5jA/I3FvjbguTDgB1qJh4JAeyiVPRd+6btoi4zDSTp90FyC+KvPl3bE8vVeC5TbEsL9j
         bP/qfvHEbDfhdGww7UJJpyC7yakKkLzzi+iXa+4qzImFIWIAO16VbvHdMNVjHvCDxz8Y
         0Kr/6i7ItZyruOepkSc/y8PjHAXLxijj5DSfRUfrE8Lo5M8giXJ5DXBj+aKzu6kxy3SV
         tfcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ChuXvyLt;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734636839; x=1735241639; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=js51kEbp+GN6LLwgWGp9XmePWQwU5kNxLYvG5BoxL+M=;
        b=jnLct0Lu/NVqu+Zk56DiDM2ZUwZd3TGI2RuWRiiD0GvKryVX0T+sV8dytB4segilr4
         3dHvS8MCWfbrmYlncoD3qghaMsOLSAOiP49I7DorzSs5NzU6QbFAxZkLS7XI81zVOFxe
         jN+SMkApotqViBa4UViEADRPyK1sMaukadg3ssia07qek31eC3jgNFXncrPZZ4OoqKGa
         2MxLlPiNdJSuYu9vysCqK+wB0M9BEvsr7XeQR9ZFd1k8TsB1vs9wTcGwDtjlPkbF3SH6
         fGEzig5yDpNPExvZbbk4W64AfCAU4wKjga+cm24aZ1wC8HpPsAwxhuM/68q/EIzQTPpY
         qMAw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734636839; x=1735241639; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=js51kEbp+GN6LLwgWGp9XmePWQwU5kNxLYvG5BoxL+M=;
        b=IuAOIgpoSHUwQIUtjUZwL16tYoXXyEjrKU2tL7oxcctWW79IPYW5WTgQ/+Bg5cDOgI
         Po/mCY4re8Z8YPr2kphHJSyVM3JAaXjgHWnxEsQIfx0KptbE2naG5D9jCofZS1bLPl9x
         KC0SDuj8d2XVlXvSO5J5YQX5KEDA96r/AsbDxeURcF25Z1BwnbY3o1UFUsnh2Povu2/L
         cqbnwDCM3yWti5llhT57DJIGxi4jxS+wU+plSybyu54ysKmaHoNaneImxMqEBqtPvKyM
         9Xqb1Nzw7tDr6ga7+7/pgJYZeZvzkRy0d5kJAwqb/yd8nUOZLkao8hI2658tm9jAlYFE
         fK/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734636839; x=1735241639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=js51kEbp+GN6LLwgWGp9XmePWQwU5kNxLYvG5BoxL+M=;
        b=mNwRm7u5UZBaIIvhlvD19lVn1iQdj6GL33aW5n8B6Gqbar0HqgSM1kWRqFBjUoVTRT
         MbvI+FC8/6lyM5yqOa04D4cSdpHrSMYD6N5CeaR42GpSktQzkiusVr/5QRnxALclsb/S
         WyO+7dCg1W+YuJJvHJOkKKlMia8SIo6okXL8lmqPp5zU7zBwBFqGnknkHq+hz1vLPgxj
         BWpZ68/N+cUyAmSrXO5qpfh07DSu0vwx/Uqw35vGiTU8aVNzYPxwN9WiIIA7jzhyKkKS
         FyS/DOepgoaDfvd5/DxYxJxpDSYWaNlEB+WQZXeksB9SSuoGQE+2xtL/gAv+AsgCUBfb
         whxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3oiefv636LfYuC8JZEVecpe9pXzbAW8xs9oOQpk/YuvR9GBtUQfqCv22kOCJgEU4ZgZLW8Q==@lfdr.de
X-Gm-Message-State: AOJu0YxHVDX9Exv6MFBASDh0OeZ6qGGGiuAFjw3haFTNy/g71gkVMb5v
	CvKHbprkaurlvIGcwzFhwOFYnAsfC7IRzXnowvk4rO+uFEaxtBVl
X-Google-Smtp-Source: AGHT+IExYD2JD76kOsHVl3sp5/1tbZMlfXR/Za9+p2o/4vK5HeYqsLkdVFbyl2xEMDvMnwlM5BMqaQ==
X-Received: by 2002:a05:6820:3101:b0:5f2:d55f:150f with SMTP id 006d021491bc7-5f62e782753mr42359eaf.4.1734636838864;
        Thu, 19 Dec 2024 11:33:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e1b0:0:b0:5f2:df60:4f4a with SMTP id 006d021491bc7-5f4d7deec87ls446871eaf.0.-pod-prod-09-us;
 Thu, 19 Dec 2024 11:33:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbOARroYlD3KBTIUjdVNd8vYImYvpr6hinzmz2gVP/XSLsUbajPbOeGqPqwCktI5NixtES2jUIzPk=@googlegroups.com
X-Received: by 2002:a05:6820:988:b0:5f4:ca80:5a3 with SMTP id 006d021491bc7-5f62e78e51emr34020eaf.5.1734636838096;
        Thu, 19 Dec 2024 11:33:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734636838; cv=none;
        d=google.com; s=arc-20240605;
        b=IfTW3a3Tw2S2R84sMTmVALMUIJRqaGhWNftaPdGYm4F5Yk7eDmOp3Arz4YdDx3V9iG
         hMitDVd18BtIPjvJXVblJjZ77Da43uEkfP8YPOCEHie1Hs2H40tOuaDGgafxIDdlzRjN
         eNgGgSE2T/Rvtj0EoAEXmY64ListswPq9exCLqLOsVHlNam+Q1E5kFUenf0bZ52BFmNd
         0OewFezTPIY/9dmgXPvorukRSTHxtGKtscBLijnE6N86lYxN2cynxE7DVUgQ7HxBXkLo
         1dNpdJcQ/npwP+lxhgTyW67vCqhU4GBvGdJH80CUvmmA0QeXIvWDXZTK7m0ZAmF3BfEu
         0wfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OYhuc5inlS1Dh76N6qD39s8i3QHaByq1kbDQ2SVZ5CI=;
        fh=SZuQU3pbeRdq8Y38jkLTQ33SG1buNu9CC1ewswL9nOk=;
        b=CwzOMiOwAiu1wikxLCWMMz/zSx9Er/fB+TqpIxcdkLIBy1AffBJpIuyd0fJP5C0Sr9
         drLuOcVnKSZY6f3RJls01We9Dvy1BkmhuhApn+Nqiupn1ig0xphBHEHY5BrUpsaQnnJ+
         +kENyxOmtaSMPnUzXgsUZu7OlgBXTjmeOVeIPaOUle/QxjZdUuKSZAGH4rYxsRvZHJLh
         QHSMe75X43EnyG/LsSddT/3ybrZ260Wo5Ol3WCwG9JmbRNOZ1mrqgWrAJwCLtFL63xd7
         0t2duNYMwZy1PTUPNaxKAsotiRfo5KqZqFmN6AkcaJGj/gUNsN2csATHu7sDeJw7VyBY
         DJkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ChuXvyLt;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71fc97792f3si75713a34.1.2024.12.19.11.33.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Dec 2024 11:33:58 -0800 (PST)
Received-SPF: pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-6efe4e3d698so10481537b3.0
        for <kasan-dev@googlegroups.com>; Thu, 19 Dec 2024 11:33:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWVfwxq8fMlXtonXsr1cdMR/c4ae9AEzx2Jd3ihztM7tvgf6mWYTnwE3sQLwmluVxLSeLZutrIp1Mk=@googlegroups.com
X-Gm-Gg: ASbGncubQMQvSS62jii2AQVnXeiXN/XIUb2QPUHZxSYMGKPZlHtWM9wTcjql218EJdF
	ZfTe5n7z0mw8+w1Vo8zPEroEfNpppQzbgc3jZ
X-Received: by 2002:a05:690c:9b0f:b0:6ef:90a7:16ce with SMTP id
 00721157ae682-6f3f544696cmr8221017b3.42.1734636837700; Thu, 19 Dec 2024
 11:33:57 -0800 (PST)
MIME-Version: 1.0
References: <CAHhAz+i+4iCn+Ddh1YvuMn1v-PfJj72m6DcjRaY+3vx7wLhFsQ@mail.gmail.com>
In-Reply-To: <CAHhAz+i+4iCn+Ddh1YvuMn1v-PfJj72m6DcjRaY+3vx7wLhFsQ@mail.gmail.com>
From: jim.cromie@gmail.com
Date: Thu, 19 Dec 2024 14:33:31 -0500
Message-ID: <CAJfuBxzRpKLqgSbjEvBJuOFdjb+nrF-REiBA0o1myZ++Z9bnDA@mail.gmail.com>
Subject: Re: Help Needed: Debugging Memory Corruption results GPF
To: Muni Sekhar <munisekharrms@gmail.com>
Cc: kernel-hardening@lists.openwall.com, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kernelnewbies <kernelnewbies@kernelnewbies.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jim.cromie@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ChuXvyLt;       spf=pass
 (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;       dmarc=pass
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

Can you run this in a KVM ?

My go-to is virtme-ng, where I can run my hacks on my laptop,
in its own VM - on a copy of my whole system.
with the tools I'm familiar with.

then you can attach gdb to the VM.

then Id try a watchpoint on the memory.


On Fri, Nov 15, 2024 at 11:19=E2=80=AFAM Muni Sekhar <munisekharrms@gmail.c=
om> wrote:
>
> Hi all,
>
> I am encountering a memory corruption issue in the function
> msm_set_laddr() from the Slimbus MSM Controller driver source code.
> https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-sunf=
ish-4.14-android12/drivers/slimbus/slim-msm-ctrl.c
>
> In msm_set_laddr(), one of the arguments is ea (enumeration address),
> which is a pointer to constant data. While testing, I observed strange
> behavior:
>
> The contents of the ea buffer get corrupted during a timeout scenario
> in the call to:
>
> timeout =3D wait_for_completion_timeout(&done, HZ);
>
> Specifically, the ea buffer's contents differ before and after the
> wait_for_completion_timeout() call, even though it's declared as a
> pointer to constant data (const u8 *ea).
> To debug this issue, I enabled KASAN, but it didn't reveal any memory
> corruption. After the buffer corruption, random memory allocations in
> other parts of the kernel occasionally result in a GPF crash.
>
> Here is the relevant part of the code:
>
> static int msm_set_laddr(struct slim_controller *ctrl, const u8 *ea,
>                          u8 elen, u8 laddr)
> {
>     struct msm_slim_ctrl *dev =3D slim_get_ctrldata(ctrl);
>     struct completion done;
>     int timeout, ret, retries =3D 0;
>     u32 *buf;
> retry_laddr:
>     init_completion(&done);
>     mutex_lock(&dev->tx_lock);
>     buf =3D msm_get_msg_buf(dev, 9, &done);
>     if (buf =3D=3D NULL)
>         return -ENOMEM;
>     buf[0] =3D SLIM_MSG_ASM_FIRST_WORD(9, SLIM_MSG_MT_CORE,
>                                      SLIM_MSG_MC_ASSIGN_LOGICAL_ADDRESS,
>                                      SLIM_MSG_DEST_LOGICALADDR,
>                                      ea[5] | ea[4] << 8);
>     buf[1] =3D ea[3] | (ea[2] << 8) | (ea[1] << 16) | (ea[0] << 24);
>     buf[2] =3D laddr;
>     ret =3D msm_send_msg_buf(dev, buf, 9, MGR_TX_MSG);
>     timeout =3D wait_for_completion_timeout(&done, HZ);
>     if (!timeout)
>         dev->err =3D -ETIMEDOUT;
>     if (dev->err) {
>         ret =3D dev->err;
>         dev->err =3D 0;
>     }
>     mutex_unlock(&dev->tx_lock);
>     if (ret) {
>         pr_err("set LADDR:0x%x failed:ret:%d, retrying", laddr, ret);
>         if (retries < INIT_MX_RETRIES) {
>             msm_slim_wait_retry(dev);
>             retries++;
>             goto retry_laddr;
>         } else {
>             pr_err("set LADDR failed after retrying:ret:%d", ret);
>         }
>     }
>     return ret;
> }
>
> What I've Tried:
> KASAN: Enabled it but couldn't identify the source of the corruption.
> Debugging Logs: Added logs to print the ea contents before and after
> the wait_for_completion_timeout() call. The logs show a mismatch in
> the data.
>
> Question:
> How can I efficiently trace the source of the memory corruption in
> this scenario?
> Could wait_for_completion_timeout() or a related function cause
> unintended side effects?
> Are there additional tools or techniques (e.g., dynamic debugging or
> specific kernel config options) that can help identify this
> corruption?
> Any insights or suggestions would be greatly appreciated!
>
>
>
> --
> Thanks,
> Sekhar
>
> _______________________________________________
> Kernelnewbies mailing list
> Kernelnewbies@kernelnewbies.org
> https://lists.kernelnewbies.org/mailman/listinfo/kernelnewbies

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJfuBxzRpKLqgSbjEvBJuOFdjb%2BnrF-REiBA0o1myZ%2B%2BZ9bnDA%40mail.gmail.com.
