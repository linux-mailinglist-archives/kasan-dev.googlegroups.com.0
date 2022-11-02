Return-Path: <kasan-dev+bncBAABBIF4Q6NQMGQEKZLPUSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49BE6615908
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 04:04:03 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-13cc24bcecbsf4729687fac.14
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 20:04:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667358241; cv=pass;
        d=google.com; s=arc-20160816;
        b=P8eKetOSYIB07xwRxRXrTYMdQ+sLF2ejVHkVRVTK+PFshxB2N4KwkF4hP4j1Y2uBly
         avbJ9TAYgssl7+/bBWw1R7Z5NrWB5jEc9dQv0vSZcsVBAci+N6G6q9InJ1izLHwFJHCW
         kbLeqP2rM0P49gNImbkaRp5Sf+u/7SAK4j9t1Iaoq1Y7K5ADtzPiAHgNxmPjs0kCyhgm
         cDpM2BxGbUgzxVjK+hXzTuBWupjQFhX49D2cIKVNYCcWtD9f0f+dN5PL5ph1Lj8j4PN4
         IMDvEu3JXyxdeh2IsftWBX6sSu/iD41tWyDUqo0cnYQuP384zudYBXTgMGcN5YHMaJL1
         4diA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:organization:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=8K9haJtNc5qNhSZYYdBU5BBYuFJ1L0D4FnNNLIT4nD8=;
        b=bdKuIg5yR/4CjffEfF6Gq5UyqwesM3v1vDJ0ck1gD9qvjj2MEoCF/A7GLaScaEMADH
         iWy5othfndF3mg+ZG1drQ4H/YrAXMCofj0MzEvoZdHhwVMKRbeSCFnFOSfkbBS24/t8X
         koSZtvj2YZPhof+1ces7Nsne91OUMwe52bUboz3bJ2ovL7C2RIWcLjwR01FET9YbLh+i
         +EEZ9WvYtj0iFh+hIxhy/gK43OZ80HES47txgUgpsqIYp2U7+2OZTZNzQOEOZKCIl4QQ
         L6qSaW+F9jMABaljdrLYJSLMnM/bzQmudb1Af5PRe0QncEyU6v6wOx7H8l6ZwKg/bknF
         qFdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8K9haJtNc5qNhSZYYdBU5BBYuFJ1L0D4FnNNLIT4nD8=;
        b=L5igvMIeWxzpbRBh+q+Rk7CtoG/hCroSCt3/SjVTo4AaU7dJm7qEAG/KdV7HkAoilZ
         jpSFFxCwnrU+r2USxWi694LwJZjtLQI+QQKW3tw7hh1SI9lDTtpoCYrI8cD/dh3JzhcN
         7/bnEySGz1KcADkXtmdgbMmtsui/da4k3xKQ0zTFnVj8niXbz7AlYSo0Md6K3LvG/r8v
         5Fy9UMi746xrwWOwUAO+dmqFj/jHf8//PaUuEtIOaawtWVfw+h0alpswdGqQXU5fwQbH
         QWrwyZebvAmy/W/z9yuMJGGxb3xunrh7SSkwr5yn+JZq/H3co5EmCL6KUTSmnTYXoABt
         54wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8K9haJtNc5qNhSZYYdBU5BBYuFJ1L0D4FnNNLIT4nD8=;
        b=1EG6ECI18Pl+qXblrx+/cSVpbxdVXz067Ay9qF0Apx4R4M7TBxXP2Kz9thLcPLvD8A
         /zKyxyaU6Wc8yqyxuU/AcSW07vOMLfsdWYIUII04ISX4qXVENJzxhmbqXjW/FgUzlbBE
         TG+YHkgRXt0MAaXflWDRcIkupZvIgaR/dBLSbx9gksF9UbXzcmE1k4lzZIUgC7vXHhBq
         V2P1QZxbztK0s8jsNKewPwmCCpBqfVATLFHqnFKwvBbHH3DmegZ7oHbDJ9uvDsqil1BY
         cQMM6Xjyvdhw3xZaIsMjZe7Rxrld6REk1ZSpg40tdJA0QpCawIvX6BL6rh5qIW7mL1df
         /nwA==
X-Gm-Message-State: ACrzQf2PAafkOJQGoPcLOeoS00jMkf1C9KAjOq1fEgEeza8Z1CbkJsOC
	ou9kPJURnXzgl/hCiV2DoPw=
X-Google-Smtp-Source: AMsMyM5bzehVoOzPlV849PjOdg+VyzpCXsxYHxs0jkjRlwJ7G/sSNDjw9NLACqU3IYfNBh6N3SZ5tw==
X-Received: by 2002:a05:6830:190:b0:66c:34fc:e304 with SMTP id q16-20020a056830019000b0066c34fce304mr11104525ota.248.1667358241076;
        Tue, 01 Nov 2022 20:04:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4e1a:0:b0:350:a26c:b39c with SMTP id a26-20020a544e1a000000b00350a26cb39cls4283577oiy.4.-pod-prod-gmail;
 Tue, 01 Nov 2022 20:04:00 -0700 (PDT)
X-Received: by 2002:a05:6808:1248:b0:354:2c04:c35b with SMTP id o8-20020a056808124800b003542c04c35bmr19319857oiv.143.1667358240743;
        Tue, 01 Nov 2022 20:04:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667358240; cv=none;
        d=google.com; s=arc-20160816;
        b=NiYHTPbVkTYrTrRFlSqd7Ai2I0xjZy/JQc75ZabOMIOz6oRUcd9ziLgVhZll/wz2yo
         Kvv4Yq32GZBIBK3NJ9tyPTUMMoy2/ASdRUJ1cBWS8VsoCxJGTs5/IaU/WB70cnHTxcTi
         T/Dd8aAap19g0vOiK5ayuvW447cc68/BdLg1jhnKDtwrOZdnWMNUiHsU7BFLD7fEr8b0
         COuXop487pwWY1C++7QHhZGttgBDPRcUSDdhuYpY+argeMk9qmoYwevMzLLd8pAtRohi
         Ns/5QerxsL1U+cgsHwlsBroAiCCAYFtlxZOGOKUQ4lqZMWsMDKB4pkqpVAF2k2IyYh7J
         RLBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id;
        bh=KQvWv3mC3+foxrp/BeHsNj2yAa1JuS/UTbWcp2YdeHg=;
        b=peiqHAvRe7xDJKRsY90y80xKDCE7hHBq91iIgOW8/hDj2eu3bsanOG7VKrl3LGQMvP
         EJdVKgbkSJ0+HvmSPbU0huUYCZUISwEj60SUdwhb2jTt/m+CNdUC+74KaaoVhE0QTUEA
         31Q63JJgGoHXDGvbSd/+dP89TqwYp+KIQRXuPKA65nqRGl7g3G/H1AZ1C+yc1RLYvrjo
         FwEAcNUxW2csKBHOyXORbsrHRnG3KPgWRJffTDkVIKSJzo7zmnoxYPt5yPY4F2TYz6uW
         hXyY0zkA11IP+Zv73BqWyZwWbOedoqwbTkfIaNCgIkGC5a2Zmf150wRapjJSr7kKLwYq
         7EPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTP id u20-20020a056871009400b0013191afecb8si781774oaa.2.2022.11.01.20.00.04
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Nov 2022 20:04:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from canpemm500005.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4N2BSZ5f6Vz15MHd;
	Wed,  2 Nov 2022 10:59:42 +0800 (CST)
Received: from [10.174.178.197] (10.174.178.197) by
 canpemm500005.china.huawei.com (7.192.104.229) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 2 Nov 2022 10:59:44 +0800
Message-ID: <ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
Date: Wed, 2 Nov 2022 10:59:44 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH -next] bpf, test_run: fix alignment problem in
 bpf_prog_test_run_skb()
To: Daniel Borkmann <daniel@iogearbox.net>, <edumazet@google.com>,
	<davem@davemloft.net>, <kuba@kernel.org>, <pabeni@redhat.com>
CC: <linux-kernel@vger.kernel.org>, <bpf@vger.kernel.org>,
	<netdev@vger.kernel.org>, <ast@kernel.org>, <song@kernel.org>, <yhs@fb.com>,
	<haoluo@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Linux MM
	<linux-mm@kvack.org>, <kasan-dev@googlegroups.com>, <elver@google.com>,
	<glider@google.com>, <dvyukov@google.com>
References: <20221101040440.3637007-1-zhongbaisong@huawei.com>
 <eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net>
From: "'zhongbaisong' via kasan-dev" <kasan-dev@googlegroups.com>
Organization: huawei
In-Reply-To: <eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.178.197]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 canpemm500005.china.huawei.com (7.192.104.229)
X-CFilter-Loop: Reflected
X-Original-Sender: zhongbaisong@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: zhongbaisong <zhongbaisong@huawei.com>
Reply-To: zhongbaisong <zhongbaisong@huawei.com>
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



On 2022/11/2 0:45, Daniel Borkmann wrote:
> [ +kfence folks ]

+ cc: Alexander Potapenko, Marco Elver, Dmitry Vyukov

Do you have any suggestions about this problem?

Thanks,

.

>=20
> On 11/1/22 5:04 AM, Baisong Zhong wrote:
>> Recently, we got a syzkaller problem because of aarch64
>> alignment fault if KFENCE enabled.
>>
>> When the size from user bpf program is an odd number, like
>> 399, 407, etc, it will cause skb shard info's alignment access,
>> as seen below:
>>
>> BUG: KFENCE: use-after-free read in __skb_clone+0x23c/0x2a0=20
>> net/core/skbuff.c:1032
>>
>> Use-after-free read at 0xffff6254fffac077 (in kfence-#213):
>> =C2=A0 __lse_atomic_add arch/arm64/include/asm/atomic_lse.h:26 [inline]
>> =C2=A0 arch_atomic_add arch/arm64/include/asm/atomic.h:28 [inline]
>> =C2=A0 arch_atomic_inc include/linux/atomic-arch-fallback.h:270 [inline]
>> =C2=A0 atomic_inc include/asm-generic/atomic-instrumented.h:241 [inline]
>> =C2=A0 __skb_clone+0x23c/0x2a0 net/core/skbuff.c:1032
>> =C2=A0 skb_clone+0xf4/0x214 net/core/skbuff.c:1481
>> =C2=A0 ____bpf_clone_redirect net/core/filter.c:2433 [inline]
>> =C2=A0 bpf_clone_redirect+0x78/0x1c0 net/core/filter.c:2420
>> =C2=A0 bpf_prog_d3839dd9068ceb51+0x80/0x330
>> =C2=A0 bpf_dispatcher_nop_func include/linux/bpf.h:728 [inline]
>> =C2=A0 bpf_test_run+0x3c0/0x6c0 net/bpf/test_run.c:53
>> =C2=A0 bpf_prog_test_run_skb+0x638/0xa7c net/bpf/test_run.c:594
>> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
>> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
>> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
>>
>> kfence-#213: 0xffff6254fffac000-0xffff6254fffac196, size=3D407,=20
>> cache=3Dkmalloc-512
>>
>> allocated by task 15074 on cpu 0 at 1342.585390s:
>> =C2=A0 kmalloc include/linux/slab.h:568 [inline]
>> =C2=A0 kzalloc include/linux/slab.h:675 [inline]
>> =C2=A0 bpf_test_init.isra.0+0xac/0x290 net/bpf/test_run.c:191
>> =C2=A0 bpf_prog_test_run_skb+0x11c/0xa7c net/bpf/test_run.c:512
>> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
>> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
>> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
>> =C2=A0 __arm64_sys_bpf+0x50/0x60 kernel/bpf/syscall.c:4381
>>
>> To fix the problem, we round up allocations with kmalloc_size_roundup()
>> so that build_skb()'s use of kize() is always alignment and no special
>> handling of the memory is needed by KFENCE.
>>
>> Fixes: 1cf1cae963c2 ("bpf: introduce BPF_PROG_TEST_RUN command")
>> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
>> ---
>> =C2=A0 net/bpf/test_run.c | 1 +
>> =C2=A0 1 file changed, 1 insertion(+)
>>
>> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
>> index 13d578ce2a09..058b67108873 100644
>> --- a/net/bpf/test_run.c
>> +++ b/net/bpf/test_run.c
>> @@ -774,6 +774,7 @@ static void *bpf_test_init(const union bpf_attr=20
>> *kattr, u32 user_size,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (user_size > size)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ERR_PTR(-E=
MSGSIZE);
>> +=C2=A0=C2=A0=C2=A0 size =3D kmalloc_size_roundup(size);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data =3D kzalloc(size + headroom + tailro=
om, GFP_USER);
>=20
> The fact that you need to do this roundup on call sites feels broken, no?
> Was there some discussion / consensus that now all k*alloc() call sites
> would need to be fixed up? Couldn't this be done transparently in k*alloc=
()
> when KFENCE is enabled? I presume there may be lots of other such occasio=
ns
> in the kernel where similar issue triggers, fixing up all call-sites feel=
s
> like ton of churn compared to api-internal, generic fix.
>=20
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!data)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ERR_PTR(-E=
NOMEM);
>>
>=20
> Thanks,
> Daniel
>


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ca6253bd-dcf4-2625-bc41-4b9a7774d895%40huawei.com.
