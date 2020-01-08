Return-Path: <kasan-dev+bncBCJ4HEMQYEKRBLU63DYAKGQEMQZS2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 21F66134917
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 18:19:44 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 14sf1891232pjo.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 09:19:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578503982; cv=pass;
        d=google.com; s=arc-20160816;
        b=V0z8pX8xBhue56Veuf1OhvtEbKWeEj4P9g/2/sP438tbualMCk4RiqD1saMABHJ9Cx
         La9sY9TCXokfwLTpFlgMFXZemahjHIAut+KpTIZARHCyCaewDOU/RNxW7x20NQOvSycr
         7LCx/46x3d6WHwQAcBa10rPEG5gDDExTVr65crVdo2UL05hbvUCVtYd56tR8dxtnhnso
         FU0aFvieXrpEW0Ws921iNmLAmBdi0niSf2CmCE7sXgoZkSIwO5elvVVL92VOUQYsFeub
         z6+yBqbxWMyT+caPm6Wxi21+G2xjPp8nub41X2RqM5nQkDoF+NE8XP2lbHvMzRCF5yEa
         yq7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=K2OehBknEiR6AV2BOzW/GZCh5C9dVjTuw5JruKrJm7M=;
        b=oKDOsLB7Pl5BqI4OEScPGK1NmlnFJcOhIOvvuxYxoCKfWrYu4yHefWSStibBFEUHjB
         fOYZjYEd1tH99rIG6QAI3+CHCMtGHnANf1WTNTHFdS8bI46PnJQwIIJ/Y5UfDaZvzHf2
         aNzPKuGcEtmgV92UZy/02u6J8oBqifI2nqC0t0+0kq/6RqV2uItZL7eFJtEeccUcsWhm
         cEX7wZ6HnikGHWRNrOlPHI4M3evF7w4K5qCXxPWP35ajeNHPS46SPLAx3DlajhLm+ARc
         rmGRFAOFBJjST434DPhsnXbLQ4Cc1T5X2cRBS7P+wqPQFvuyzVwurGgV1JiAxnoO0YqT
         v+pA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=Dd1rN0sO;
       spf=neutral (google.com: 66.163.189.152 is neither permitted nor denied by best guess record for domain of casey@schaufler-ca.com) smtp.mailfrom=casey@schaufler-ca.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K2OehBknEiR6AV2BOzW/GZCh5C9dVjTuw5JruKrJm7M=;
        b=mhQi6qk03yUnZ7NFBOb8ShTGGj73ipdgIl438AACnd43wxNrPujdJkAGXOLZswJULB
         83kqwyyzuCSimTr5i6fOzCBlil2OdbqulpsLBiTbqdKsv/wr30z9DpksXGcyPF3YUshc
         dIL1BF76BO8xlY21P4d6e7KohD9c/z3VLYqV3ghpuruMrZAVbHMwXOkZ+kcc/gvzz3j2
         4PyZeqMe2VsH9QepkcW3DtuFu0mimsNTJ+cl8Eznz6XZMWlLcm0qn8BxZ47h6B7DyCHF
         rIE57S+KQi6rCNoIzJMPRVVUEnHjS/C+NdcoRD6/3R8TEuKapA/j95HQUPrRT9GJl0r0
         9YFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K2OehBknEiR6AV2BOzW/GZCh5C9dVjTuw5JruKrJm7M=;
        b=rlf1U0a3uJtAkKdPB3K2kHmBiR4kpyZE5Idz7YebmkpxSMxdGhsZq89xGjxDbInr7y
         SkKf8l4xS9hzBPofFHcq3vY3n0b8fxJ/ETXx7P29+X1gZrViXM1JUde3WfVj1SNyT4Sx
         oSFbSWeM5NnA18yzOnDxU6tLHvsDfML4HxVfIsdhu0wrtwmHlUDjSGLhZTyBZk/i3oez
         FiiucPWLBxyJ+uvN/JmBYSF55LYTSDHR0DtSwGpyaqTiNxwtRdGrmvzIYLYyy4NJ0ke2
         keDmlfMvO+KhBKj+OVCOMumVWclycQ+9Avs5Zd4KtG3cBJofR5HStQ4AEa2L1ZckxwPl
         +nvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgTmMSO/rB8PbiSM8Th3boa8Vp7MdxWiajah24kgMKCRtws4eR
	8RtLqJPff6/V29ARAz3FK/E=
X-Google-Smtp-Source: APXvYqw7Hf7Gn3vn0/6YJNdIyRe736h2/UlsyLUhdvOzjLd0cfDsfXcnPhJ8XqK1q2tscZyMFK3aFA==
X-Received: by 2002:a17:90a:3945:: with SMTP id n5mr5504618pjf.34.1578503982432;
        Wed, 08 Jan 2020 09:19:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:cc:: with SMTP id e12ls1397944pfj.6.gmail; Wed, 08
 Jan 2020 09:19:42 -0800 (PST)
X-Received: by 2002:a65:66c4:: with SMTP id c4mr6406782pgw.429.1578503981977;
        Wed, 08 Jan 2020 09:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578503981; cv=none;
        d=google.com; s=arc-20160816;
        b=WUCGDiuVmDbq+gT2XtlX2VAQU/40Cgfjfq+OBfr5EHAR6RQ8m7VGcQMPIhVKGMOXj1
         mnNfhDa30rFPVfBHWL5hPTJ7A5nPRsctEyjep7KbAT8sAqv1yz8yb8FfGwsNoLhlvHjm
         Zm7PLfRxtufWUC9aBfBXoqRJLrwEVFbBZflAiXtZipbQTgVjzZhw+6C9GvQsjUDNbHxS
         LU8SWcT8jG04btCq9zaK0cqsSAHVEt2sFl05OvlaMR10evbSFcV8qBjRzXOaTK4DqBw5
         5ha399l8pmZp5yke9J2bxr1IQZE8FOB73QICcneBhGEcYV0/ceIM5Y2iGg3ftODBilY8
         OSHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=2eNrGQWjfEokt2BCu2g6eg1jgsmpxJpxKMHtqeMJJP4=;
        b=TiG4Z4g0Lf0UJClxI4eyP91LStBTcAK7Ve1s4BXt6ivervrcBwEtpv3KwlEDVjAZlf
         WI2c/bhcbSNqsP18TfDrAz2IqtwjnlBBjRGQp3o2lEn05a4x5rpACyJZOHXbtJmEHDAj
         6FBJ5YeVaxNBcdtjZBn+msBJdrlseeEph/iRBWmt5KX4YnNhsoe/u1Oeb3Gqa/xgoIeX
         ySTkLtLKf3+ouq1czQrdUKoZl1uBS3XYAmef5h8s9yFJFjbw51m7XxNQBM28vBawtnoV
         IBfWG4qNW9MpbLAoUY+HoaxvXh00ZwM3c6aXAutzoMnEWg0sqEDJw0tDm74IuyN6YvXa
         0Vmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=Dd1rN0sO;
       spf=neutral (google.com: 66.163.189.152 is neither permitted nor denied by best guess record for domain of casey@schaufler-ca.com) smtp.mailfrom=casey@schaufler-ca.com
Received: from sonic314-26.consmr.mail.ne1.yahoo.com (sonic314-26.consmr.mail.ne1.yahoo.com. [66.163.189.152])
        by gmr-mx.google.com with ESMTPS id c24si80397pjr.2.2020.01.08.09.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 09:19:40 -0800 (PST)
Received-SPF: neutral (google.com: 66.163.189.152 is neither permitted nor denied by best guess record for domain of casey@schaufler-ca.com) client-ip=66.163.189.152;
X-YMail-OSG: ob8EuWwVM1nsIDYAJAkwumRxznWgB_J6vMTC7M2ZzuEB5GthqFJhz8JI8imxxn0
 fs7bStGejWAKtD89d3sEapJxCRHI_wwjivoZNS5SXJCpEgkORvms9VhX8QXkrtDaRvdiioCHzdF0
 5U2cXIAgOmwKA0RM1EwG3x9beL6WaLfgwVwBw1wjocPEaYazj1nUPs0fzR9cFvnzu1lxigW57zU7
 rU0FUmtwFXE570dcUnrK20AoigdDSAbrTY4bVobVmGJgPCn7lS5I2O2te138U0OCb1IVAWnm.MOW
 L6brQ97TNjeGkr8IAHt6vLjprMDAiNi6.jGHBU91.ui8ZzYb.Nqsu.PAQyYUCimmf6VC9n8UVoo5
 meMwmIdhvmrhKngWNGLubeyTXG7Wn4p_VnLkVPLQALZ_wVLy3ah8QKKAMc_9HnpF7xiMbTdv0HOr
 Q2DyCleHSJBgUGlqKFIJQVpUgy1aIcTFnHYyfX1wvwRLScbTH07XqNJ70rThbJuf4oBpFTT0E.84
 kxfVrxDMTOp.svTApMFJdFe.hxQ_.cp1Ue23ZjjrGqkF.wk23XNJBsA0NvyMtrGrw8SxLOTCO1lS
 cXuk2SGdOQ2oYthSm0ax0zt9SmT7vaqbvLMyNVSENzK0.kJ_6SwhUZJ_ynHKbD6vVKCIWHPIAyBT
 RYFGLMtnqIRXGeiugPmVFcNaBGDvGqKm5mKi6EUCOn7zymJMdNw1JBsETgjKiIz5WCg4Jnihl3jp
 swu99QHj7KPe29RmtkIAw8cRp_fQ_woleXuWGVMLB_39B8N3UJq7T9J9XpiOpxhWrr2PliA5upYv
 EsuozVZQ1KW57bGkpLNQST3LjK7q3LHZOosWjn42lR8EqFQi0txKJQC7XhbSCRrT6MAcaV3gpgw_
 .qoiBVP.g6Sx_065aM9Z.17FgaflqaAm0efNO_t_S02U7L.Wa_ng5bbDyBlMTNMLCQY32i4SXPTa
 0eCbtIRL2LIfPWSrDG.qvPBbHRJ3.25AnxLrj4VhIx83BGsNzqvgpAf4KV_SFblDBmsDfOsAuvMU
 v5RFEdK7.WNjmIqIwb5Cv2czpGfUIoBdYjBspHWX9pZi.n6y8fnCYv5lrEoNVXSDsZf.wLexP5tn
 kD8vtypMFRPzTAXt2NEtwmXjYMUEED.siM2hnYRF09SCSp27t414KPPM2.NpIi3kXrsn4zhJagRk
 pR5uaYHSRuQKwuzhvvYzx1EmvdVulp7mREIwyKqsEy4vl.KMgIpft28CrVxcZVfcbQxsRxgRDkan
 j27lX1NjDqP3Vbf7XbUbQvnw1PuKfplz00WeOxI24F6MkGq0W1Ti_Ol3A9nnjhAYpkJ0cIYLGY2V
 uKo9Vvdyho.fhnpl9IYvguXgnYADCpFT8Ad3ghJWnmluzZGbFxIdgTucr0rsbBj7jI0j0fNsTTmq
 Nkg4hR03ST0yQ8iuSAc6BqU7w3_Ge5ziDmmCYqAF98fi6i5rIYjN6h7faFRmt5MTwer6i0Sk1h2W
 _HSPYYcmsO_RWleEYTwAm4YC3xZKbVTW4ouo0CZeTjA--
Received: from sonic.gate.mail.ne1.yahoo.com by sonic314.consmr.mail.ne1.yahoo.com with HTTP; Wed, 8 Jan 2020 17:19:40 +0000
Received: by smtp427.mail.ne1.yahoo.com (Oath Hermes SMTP Server) with ESMTPA ID 31b37889f22c2f7107f5eefec060136d;
          Wed, 08 Jan 2020 17:19:36 +0000 (UTC)
Subject: Re: INFO: rcu detected stall in sys_kill
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 LKML <linux-kernel@vger.kernel.org>,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Casey Schaufler <casey@schaufler-ca.com>
References: <00000000000036decf0598c8762e@google.com>
 <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com>
 <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net>
 <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
From: Casey Schaufler <casey@schaufler-ca.com>
Openpgp: preference=signencrypt
Autocrypt: addr=casey@schaufler-ca.com; keydata=
 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
 abzjfg==
Message-ID: <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com>
Date: Wed, 8 Jan 2020 09:19:34 -0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Mailer: WebService/1.1.14873 hermes Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_181)
X-Original-Sender: casey@schaufler-ca.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yahoo.com header.s=s2048 header.b=Dd1rN0sO;       spf=neutral
 (google.com: 66.163.189.152 is neither permitted nor denied by best guess
 record for domain of casey@schaufler-ca.com) smtp.mailfrom=casey@schaufler-ca.com
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

On 1/8/2020 2:25 AM, Tetsuo Handa wrote:
> On 2020/01/08 15:20, Dmitry Vyukov wrote:
>> I temporarily re-enabled smack instance and it produced another 50
>> stalls all over the kernel, and now keeps spewing a dozen every hour.

Do I have to be using clang to test this? I'm setting up to work on this,
and don't want to waste time using my current tool chain if the problem
is clang specific.

> Since we can get stall reports rather easily, can we try modifying
> kernel command line (e.g. lsm=smack) and/or kernel config (e.g. no kasan) ?
>
>> I've mailed 3 new samples, you can see them here:
>> https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
>>
>> The config is provided, command line args are here:
>> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream-smack.cmdline
>> Some non-default sysctls that syzbot sets are here:
>> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream.sysctl
>> Image can be downloaded from here:
>> https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does-not-reproduce
>> syzbot uses GCE VMs with 2 CPUs and 7.5GB memory, but this does not
>> look to be virtualization-related (?) so probably should reproduce in
>> qemu too.
> Is it possible to add instance for linux-next.git that uses these configs?
> If yes, we could try adding some debug printk() under CONFIG_DEBUG_AID_FOR_SYZBOT=y .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d009462-74d9-96e9-ab3f-396842a58011%40schaufler-ca.com.
