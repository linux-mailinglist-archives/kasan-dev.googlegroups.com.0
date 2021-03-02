Return-Path: <kasan-dev+bncBDLKPY4HVQKBBC4K7CAQMGQE2YGOKIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A51DF3297D2
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 10:27:39 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id v1sf280589wru.7
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 01:27:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614677259; cv=pass;
        d=google.com; s=arc-20160816;
        b=IHwRuvvkD3QKmGjUQJfg6QyL5wtk6ZJ2V2+65mroGiUdaZFTlvMHnGCnzsAwiom/kr
         RmbUweXZV6btN9UQ90GT/H1FXVy9Iz+lwI6V6I/lsxyZYeWo+CraUIYkfywsd9zwnhen
         R7smq5EQwdiSZPDdLdvuN4VC6GytCwVKvOMJv0WsWlKYS0QghjmUC2lES/mLPXR/Ho30
         S6pP2rqe55YyMeE1kaVgKVYq/gpqvYgK9NOqxIPPaKa3bg1eUbNSiQa3niKyeJYmSt8y
         Tpbp8m/T6fVtOdNdtjJqtwTBUBYBolMvPjcA0gIMlVRJSmjNbkjJwMa60SYqA4Em8oU1
         uHow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=/zqTL+0Di+WzaOEGua3us1/0fZ1l/ufp/t7gZx/Ulrk=;
        b=u4+Iyk7X9yW5kMUwNjenXVE0XotOlSeiFcYSQlUzMkxt48G+ojAy8w6r8LgtCS3Jwo
         z+Dk+TBsyvqRxBYlvonGvIBlPZEJj7LvtEVFwWkcJjh7NWyFYfowBnRwugIwTfIBOEyn
         pK8CRgtAJP4ydDEH5lrtPrBFuvjutMkwVaOBPGq9niSi0vgZW1nkZjcwAKi21ZZqYyvE
         MMlYfTVuuT5JgyMQX2aFIKvwk/eerLVK1NEABmRDI8EUXn8XuTbhAQX+ipuMG/p5jWjP
         PV6zeXsiX+d8yxf6Pk+6tEDHacUyd90zRbUpjwhiPkkQpu3lYOtQrYeQcFNnFt2rcxsX
         H+Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/zqTL+0Di+WzaOEGua3us1/0fZ1l/ufp/t7gZx/Ulrk=;
        b=cXS+93NIcARxyitvpdxTyRdjz91tdEFo2mhCfPcKZLUkUN1WlXMZ8Zdulmu3E5ZPVR
         27UxWvO4tvwRhGcp/QwW9tyx/w0BD1rIsIWhpIntmuILmaOvohR42MOrdlJOeCa0W8gV
         00vaOJhhx/D1gdY4pVt2QZ4QWeOtance9UXhiVW6L1bs2K/5SZanRrgT+kxo2pER0kGe
         fcLLfvo3sh9jMQ25eY+XRMDwCB/G0PVR228sj2IUae3Hna2S885CRCB1RznWimf5w6Vs
         HDXLWfZZYfiUEPyhQMb9FyQmyJh0QpL9n5TEu3EjkDlmyZg1sFyF8wh2QxE9q5rceWgM
         q1vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/zqTL+0Di+WzaOEGua3us1/0fZ1l/ufp/t7gZx/Ulrk=;
        b=n5lteO1k8VdigMU5a5REjgyYTA+7CL3GKGGRIFI0rHha9qXXM/et8awqO1Yy8/WLNa
         h+aes/jA+Q23Se0G+zVOcXIZVeTF9pXZw4qgiSObr6ew+HdLdcJwjD/pX7D6zkwU+uGV
         yTgK5hf+l25Ei8gIC4geNC6HI5GBavpOU6ATIJWzr4eiVmptHn8t4E0vejJyjeXRoqP+
         8T5Ju4OtVOGLVytYFFUU0U9JZ/dvrlbe0EStdcewrcq3GyglUxmq9rr6z7tlRFypOZ38
         aW1TV/vjYyID0VnTD/Fvig0lAav495D775yut6mwkiEXzFn0tf09AAJDvZ/BRfKEoBxU
         JEHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RbUBIgmWZWT0m6Wcq7uWJH1W91uA1S2b6l1bEW0uEW4JfGWo9
	KvEBIUzPWE3xI3d2JYHGwxc=
X-Google-Smtp-Source: ABdhPJyrMnRh+DxWvYoIqgA/wyfDfAGDHjottIB7NLuCX0RsUItfOUf3MZ32mCtXLLx8UI4mYCw0+Q==
X-Received: by 2002:a1c:80c6:: with SMTP id b189mr3081915wmd.21.1614677259281;
        Tue, 02 Mar 2021 01:27:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a89:: with SMTP id s9ls14653902wru.2.gmail; Tue, 02 Mar
 2021 01:27:38 -0800 (PST)
X-Received: by 2002:a05:6000:114b:: with SMTP id d11mr20563049wrx.318.1614677258284;
        Tue, 02 Mar 2021 01:27:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614677258; cv=none;
        d=google.com; s=arc-20160816;
        b=MvJ8JKNLFPQIv3t10WNlxunqhNnbOC+2DDvWzXL0Jtx9I//xEKhZeEcUcboZosIJXc
         7CtUyJAh0Q923H6GdtB6hNi8W2JToBrRD2dfBX1oaQRvD2znsRfuvF4QyRD9zdPC8+zg
         9gc6Mdi8uN7Rc62DOvkU5VHzbCOT/maS/KGIt+YhZBxybXXiImWqd0N6GzWJTYKXnrYJ
         hsjCknrE5YhBqozpFY/rRJQ5G+rpsrqSz2Wn19slrkHXQlrcFpIJ11UMkP6ru/qjaRfJ
         Et2y59NOTEGd66y4Q8a/pPWctCtAdEkLtAtg1cmn8MZ/hvZUEn2D/zj0unsJ07caQGY1
         +Law==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5U0yO6mpcTrj5czUwTfm+ZSogLX/QDxnzF8w9zTTXGU=;
        b=FzinUpp/TcJCLTP4gCS0UaOZAJraKNufbGUryzTLslQXMew/FefiJhvbH7mcv76jSE
         sYmOBgwSamy236MncSRY3OzFCQj6ueMnMPQEQ4I6gBkkhL/C3ZwSHXXwEGK6GjCA9+gU
         mQ64PSIF1MA4TZPBGJKwvd9w5+ZvaxCWVF8NLkedaiGwafKgV5mZRMT5/hYHoYBN1E5C
         kL1qbSf6GJT3OrAcJmse2PKhSRDZzf+PQK0M8VUObY+vecAiIOdPW4zpcgE3xSXlysq9
         sKYaKcNQCy8gh0221Si8TnLxZNHonMV+Nfg+MN9Ka+nMbAfdVyugXVa9iEQ/YHXoIJXo
         lOxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id s1si663499wru.4.2021.03.02.01.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Mar 2021 01:27:38 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DqWxh65Czz9vBLF;
	Tue,  2 Mar 2021 10:27:36 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id D2UnChWDqhR1; Tue,  2 Mar 2021 10:27:36 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DqWxh58jrz9vBLD;
	Tue,  2 Mar 2021 10:27:36 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id CDBF28B75F;
	Tue,  2 Mar 2021 10:27:37 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id nNec12v5Mb1w; Tue,  2 Mar 2021 10:27:37 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 310CF8B7AD;
	Tue,  2 Mar 2021 10:27:37 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
Date: Tue, 2 Mar 2021 10:27:35 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit=C2=A0:
>> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x=
54/0x23c
>> [   14.998426]
>> [   15.007061] Invalid read at 0x(ptrval):
>> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
>> [   15.015633]  kunit_try_run_case+0x5c/0xd0
>> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
>> [   15.025099]  kthread+0x15c/0x174
>> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
>> [   15.032747]
>> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfenc=
e/kfence_test.c:636
>> [   15.053324]     Expected report_matches(&expect) to be true, but is f=
alse
>> [   15.068359]     not ok 21 - test_invalid_access
>=20
> The test expects the function name to be test_invalid_access, i. e.
> the first line should be "BUG: KFENCE: invalid read in
> test_invalid_access".
> The error reporting function unwinds the stack, skips a couple of
> "uninteresting" frames
> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L43=
)
> and uses the first "interesting" one frame to print the report header
> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L22=
6).
>=20
> It's strange that test_invalid_access is missing altogether from the
> stack trace - is that expected?
> Can you try printing the whole stacktrace without skipping any frames
> to see if that function is there?
>=20

Booting with 'no_hash_pointers" I get the following. Does it helps ?

[   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x54/=
0x23c
[   16.848521]
[   16.857158] Invalid read at 0xdf98800a:
[   16.861004]  finish_task_switch.isra.0+0x54/0x23c
[   16.865731]  kunit_try_run_case+0x5c/0xd0
[   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   16.875199]  kthread+0x15c/0x174
[   16.878460]  ret_from_kernel_thread+0x14/0x1c
[   16.882847]
[   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
[   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B=20
(5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
[   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000000
[   16.918153] DAR: df98800a DSISR: 20000000
[   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 00000008=
 c084b32b c016eb38
[   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
[   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
[   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
[   16.947292] Call Trace:
[   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x23c (=
unreliable)
[   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
[   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapter+0x2=
4/0x30
[   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
[   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
[   16.981896] Instruction dump:
[   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 907f00=
28 90ff001c
[   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 812a=
4b98 3d40c02f
[   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/k=
fence_test.c:636
[   17.008223]     Expected report_matches(&expect) to be true, but is fals=
e
[   17.023243]     not ok 21 - test_invalid_access

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f806de26-daf9-9317-fdaa-a0f7a32d8fe0%40csgroup.eu.
