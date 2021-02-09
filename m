Return-Path: <kasan-dev+bncBDKYJ4OFZQIRB2EYRGAQMGQEQF22YYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6548314AAE
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 09:48:41 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id l4sf5559326oif.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 00:48:41 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WBKNuOUfOwmXCj4zWsV9iF+LxxXA/hnuts1Rtc9XR2E=;
        b=NV58wuzTcVaij3RtM4lIKGg/B5oujH0bmlWyziCckVr2WEhkHGURjUa2Ur2JYtmXal
         Jwa/E91/1GSi7aXlJsK022oRKiJ4JCv7UGrrT5a8HYdd3VodNkVbFZE6s2OtRIT7lbEw
         y1Ae8sStddpSq6MbD73C7xPTZWLK2OO6ViCZyMUIecMj02jadmdJX/n+nNKeVGLVtNR7
         fLb/bpA9P4RTNxsoVUCOu8KNkYYfM4s8tT5N9qPudufeskmrnjv6BYNG0tFoUfkJfxz9
         R5qFV5EyTPJmfNrvHn8T4S8/GLmBXAo2P3dvNlKQK7cJXlNKpfN5qISpf8tFOdvl2PUz
         a76A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WBKNuOUfOwmXCj4zWsV9iF+LxxXA/hnuts1Rtc9XR2E=;
        b=Llf7O3U3T8pOZ5iOlcqwTV8K1Qh+fSXEWxI6IFk6BZml3ibybKEF7hUPZAeGtmww6n
         nEt96sj/depL2/ZV4n9KHd8CliFI+bPOGVjLGPL/VqTNooTjSqPwcw7g3B6fm6mjekxA
         CmzFmAF3AB5AbUpZ/J8mNa9Z2NlK/d/gWjqTZUHfW+VNA+/uIQuNUH6gjHxDjW7fCU2E
         kCBP/4iCzxPNeLnfS8TURY/4ODZTWH3inJyNWzaVioKvTzrlmLuCwT6/WN3cFw8Pmz0Z
         8GQRh6+BW5mFNJTna0irVTDl5W8yPzK30b2ktE7MBLeTs+dS3m/b8n/egJRV70kK3AlD
         e3vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WBKNuOUfOwmXCj4zWsV9iF+LxxXA/hnuts1Rtc9XR2E=;
        b=MuYq+nbO8Fkuginoi8yeTIBsa/Yynef0Lm+o6U48z50kkBF8oGtk9eL74Y4Qy1gCNz
         x4toK0XAhAIivr+CldXEFT5x7npNYEzruI7fTAJ7mN0/7TQDrjbXW1CyZ6FPh+4mhPLW
         /55ne0XlUi5QEDBkHAXXHNorYmhY3T1nNvSdGFpTpfAg7plNsasirhYn8z3Yu9yRdT0R
         XogTfv1FusCx3RJWk2KXr1oHhMrGQwwzrRP5mPP8hM+Ya/4c8X8ml9tmoSW9VPFgC3Lv
         ncATaRBG/TrO06hIkbgVKPa6Jk617cbO+xGLbG5BpQg0bU8pEzozUY0MqC32udvpZLTw
         1SoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VO44wC5LZZqwDzAkwW4MaTqL+TCevUL/S1h3zPWYQDMjIgJPD
	b7w/VbpFU6ddUiroyYjCWNM=
X-Google-Smtp-Source: ABdhPJyYbCBoDk99e/LZyz4gkiL7eC49iTnUdpUc9dvCSl82jI3VuzgoHcsoVACEAvEwNVa8BayVQw==
X-Received: by 2002:a54:4813:: with SMTP id j19mr1802687oij.73.1612860520943;
        Tue, 09 Feb 2021 00:48:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:4d:: with SMTP id v13ls2451616oic.3.gmail; Tue, 09
 Feb 2021 00:48:40 -0800 (PST)
X-Received: by 2002:a05:6808:294:: with SMTP id z20mr1749871oic.14.1612860520357;
        Tue, 09 Feb 2021 00:48:40 -0800 (PST)
Date: Tue, 9 Feb 2021 00:48:39 -0800 (PST)
From: Jin Huang <andy.jinhuang@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n@googlegroups.com>
Subject: [syz usage] how to connect the vms
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_188_593624996.1612860519716"
X-Original-Sender: andy.jinhuang@gmail.com
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

------=_Part_188_593624996.1612860519716
Content-Type: multipart/alternative; 
	boundary="----=_Part_189_571761788.1612860519716"

------=_Part_189_571761788.1612860519716
Content-Type: text/plain; charset="UTF-8"

Hi, my name is Jin Huang, a graduate student at TAMU.

I want to ask a question about the usage of syzkaller, when syzkaller is 
running, how could I connect to the vm/vms through ssh myself to see what 
happens in it, is it allowed?

Thanks 
Jin Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n%40googlegroups.com.

------=_Part_189_571761788.1612860519716
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi, my name is Jin Huang, a graduate student at TAMU.<div><br></div><div>I =
want to ask a question about the usage of syzkaller, when syzkaller is runn=
ing, how could I connect to the vm/vms through ssh myself to see what happe=
ns in it, is it allowed?</div><div><br></div><div>Thanks&nbsp;</div><div>Ji=
n Huang</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n%40googlegroups.com</a>.<b=
r />

------=_Part_189_571761788.1612860519716--

------=_Part_188_593624996.1612860519716--
