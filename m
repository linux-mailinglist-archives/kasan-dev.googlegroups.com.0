Return-Path: <kasan-dev+bncBCPILY4NUAFBBTXQZW6QMGQEXHE7BXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A678A38AF7
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 18:56:32 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5f32b797245sf5475229eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 09:56:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739814990; cv=pass;
        d=google.com; s=arc-20240605;
        b=OWgs43j45CtxYQw4RFxSJn+Zjk24rRm+yyPaPrTDi4RXLQN+ab8NPtMzPYP/LjuImc
         F6Jm6w1W547CrFDBs8UO7MlTMfOMd8k0TnA98cqM6QPAifbT0ISM/1GKx4kTCe0DJ/BP
         vXgaFZYStHHOA/SdbigruWHg5j86Rxombckh18wGgWbSPfl5hWnV0IMGQaFmRk6ZyjiV
         DTuCWeZQrNz169P7wcLwba+6XO/0GoWllNc8CDyCoRC3fKOVLyLp+ItihngB2cWVHbF8
         kzT7AbizH4zuMSdR/x2lO1ROuoyiCAi7LAD2KtCYA45O56w/uZQYrMeV5zj1MBwUgQyr
         8TOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=ItTyVPW3Pk3R7LEjkfReYDX6HSqhkFLlDApotLmiMGs=;
        fh=GYkaknhu1Vbz44e8mKHGYDme4OUMQDTjQ9+dFLb15YA=;
        b=QsOVHa06zSakxeq0VHA6Ok1eggeBApk9F3t9d2sODmBYntLSPkZR12SDTpNp64iS3I
         Ph1+GOiAJd64ipwRDwa4ZMuLw3VJW12EK9xsfYReVNFZaIBXDwvc75DwbL5KNvaPGfyv
         x22qtEhnoI21xrwryQQjulZxriQM38GkqN8xuoWoOzVFkboIlslPy1A3YY+kwe4XeTsE
         uXfwtD7bgXFFckhyllVbyJmtApueA2sIvgfRYo1aJJYRCxNDlN29nJxOwOR/bBV3bwlu
         bKPZNshHHjWEwOS6pT+h7cmf/EQd/bxGXkhY0dlyt+YMN94hQoRtLyw0o8BtxcFoEs23
         m2iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Mdeo+KhA;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739814990; x=1740419790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ItTyVPW3Pk3R7LEjkfReYDX6HSqhkFLlDApotLmiMGs=;
        b=skCYwWnN70UBwQntEdOVyYpdiYyEiq5CTR9SSnglXPbxULk/qzQ1eXdSP3o/44O1Av
         JZPloy2tpQOwYtGq1UwoFmQWMFs8h/2pXhTShAQLAY8ejPZ6XCW3+mKiHEHhoUdYvP0w
         pz51LqQNqQlaMAw5OO8S8fdqlS6X+pf+Q5ywdGIDGmauqihZVThTnZilvcjWORh4N1TA
         ESb6YsVMZFfW+b0TsfpN5TOoQsV4iwdVp3p1x3faQPcdM8Buw40RHA9mM+5BEaJi8n6D
         7ObyUj57SykR89f6bFpb/+502rsiLQT17gzU6Fmk88kjn1+QHybW9tjV1LI6P03uaehb
         2/Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739814990; x=1740419790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ItTyVPW3Pk3R7LEjkfReYDX6HSqhkFLlDApotLmiMGs=;
        b=OFmb0gtt86TkqtQ1bCRbFBWXuZnf0wFuwWX4yDYEbfrpS/B7OS/O/saQ6nDgIhfM4r
         0vtFLzfzz3j8ik1N8sN00ZCP5hgqvTrUhUHVY9DYkkOXptenpcRtAx3suJaaCo65PtoI
         +jqQOefa/+04jOb8TqW3jCe3/AZKyFitTuHCBif6T6i/MrEpbMjmMpJuNM8Xk6xXrztL
         SLE/NnoGq+6kzAfJZRRHjIktalSbeMSsnsFWxHcQBcCm/Y1H6UoLDf2pN6SAKzwAl5rM
         Sa/GRQpQZQRIHNkW/zY5kVRL/yhKS6HG2pnobLCpvZ4tzGhxXKPrAYeiQxN4I6XXKmGx
         q5cQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFcn6uHF7Zhd/L5uzfw4dN7H+xVrXxNy7PbtanUNHa+b3NUMWu5rRz7WQsC+yEBfmDV6huAw==@lfdr.de
X-Gm-Message-State: AOJu0YwrSAMQFdwzKMuwMBeYgsI1/Q9HknRP5RbS0+kWSMbxi67Em7X0
	04PmYQWhdJah0msUk1vsXUIVMCQ9JiefYJBekqYD0y2MF4rwzS89
X-Google-Smtp-Source: AGHT+IFfpUEF70a5r2YwUldXnoPSn9kCoNY3TfXd6c0pLwDa2V6GSDxhcCRsDETvIoRQtWuogOG3Qg==
X-Received: by 2002:a05:6820:54f:b0:5fc:92b3:2b03 with SMTP id 006d021491bc7-5fcc55c8bddmr5325653eaf.1.1739814990558;
        Mon, 17 Feb 2025 09:56:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFWrICrCcHnS8zesFx2qTb9fHhD5osIaVoh4NI63oewcA==
Received: by 2002:a4a:d30a:0:b0:5fc:edaa:b875 with SMTP id 006d021491bc7-5fcedaab8f2ls64201eaf.0.-pod-prod-09-us;
 Mon, 17 Feb 2025 09:56:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVqNP3hfcHhaxFpRSxRoHB58UEmXiZj2TYVtY0qmtXNOTdXEqKKuij+t6HnhDSDAnRKOOwvJdceYHM=@googlegroups.com
X-Received: by 2002:a05:6830:4124:b0:727:876:c83e with SMTP id 46e09a7af769-7271206690dmr6181731a34.15.1739814989594;
        Mon, 17 Feb 2025 09:56:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739814989; cv=none;
        d=google.com; s=arc-20240605;
        b=TGOcjOLXL/JtmKZd1GyW9O2CZk+/g/C0E7VlHYV4ZBAMe6Ln5dy6quspas+52zzqoJ
         RSaNI5SlZVFOL++19wINrFzwSlqVAJNlBSDcNMUy1DfZAAVi6saEbZNglMhtXoHfjR6K
         Dk1Xo85UVsl0UPy+SY1yinkaXGBHyPH3Y6qyntFL5HrfewtyIr9f1UGyS80ETermvR/j
         y2DX2ix0KUcDQaB5s6csDxIswSryv4Lr9CgVj4BSE/hIe9hQpoUBb4uEpoLR52cvCrwI
         70oRtZEhFV68WTUeZd490BGXJcWsD7el8ZUA1RAHXHVAr16WRRgknMo/dyojj9sS6SMa
         n4hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=niJ7GrqnlE8mjwkLXdroJsmq3cDp8d9woXPb/vSi3Z0=;
        fh=EKUOjIVfMo95rB8pFBO8Nv9nry0jrmS6QY7ns12zssc=;
        b=Urt6eCqjBwrQ98aiB0bcgHwQeBVQBqVWxmtiQRhCFaSd8wzoz+21EoTEVeYp61z0KJ
         SseKCYDQi9lz2RN2HGvSLctMwQwy+WzhsEqR2RALyCq1OOJV35YhEs5luYyL25SslKb8
         kWCzvjSFk52uuZYydlCDrHcqvViY8r2/VRgXyepfZmVzcgHPJIyFMMaZEu1TnQepeIZ4
         HwPCEAMzYqJECWG8+yFQ1JQ5RxG/K8dkSUYmYSVDW2nyX8MA83KpjyjIEzlJQJiupla2
         IQu36krFwdpWL7eIz6GHY8/ch9nJkwglTgOk1ShEzWyiJMwz9C4wtp5Dxs6xlVlasr2W
         vPFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Mdeo+KhA;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7270024b84esi440665a34.4.2025.02.17.09.56.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Feb 2025 09:56:29 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qv1-f72.google.com (mail-qv1-f72.google.com
 [209.85.219.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-130-BOZyqsz6OMGwQqrM9v8opg-1; Mon, 17 Feb 2025 12:56:27 -0500
X-MC-Unique: BOZyqsz6OMGwQqrM9v8opg-1
X-Mimecast-MFC-AGG-ID: BOZyqsz6OMGwQqrM9v8opg_1739814987
Received: by mail-qv1-f72.google.com with SMTP id 6a1803df08f44-6e65e656c41so85849006d6.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 09:56:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVlwtf7KNrRP8A00wXNia+yi9jD1OR5R1DoRJdsJCY4u30D76PWxbQI+Rek1lpegfYwjBBDxFjq6c0=@googlegroups.com
X-Gm-Gg: ASbGncvf/H01Z1LLNC7CbFgs7BZ6nmdq41pb4hpx/owNUEvmZUIPXCANfO2DWG0YUcJ
	OMlWxoggqlQl8p6TqGGG/1t16AELY2oFU2A8NydqrSsHQhbpN/4GcxZgg/+0S7FzgQ/Ha2arn4c
	RIokn3adNKmKrvNH6gpBX6+o8grZQyzLOv7rPMYGNTRjhdiA6S5tcKTVDbRlMWaoCBonAtndKdn
	1GV1nMrlm4KHh3mjsXBYU944Nc6I5m4p7ztkkzO8Chdri3dsXtEeKxO108a8gw73rUb2zdBbowy
	tIv2G4hGBOOpaAeqp1XlVgQSj5A9j5aqQ0G5HLSdjL4U77Ka
X-Received: by 2002:ad4:5f8b:0:b0:6e6:62e0:887b with SMTP id 6a1803df08f44-6e66cd29e70mr149586976d6.45.1739814987302;
        Mon, 17 Feb 2025 09:56:27 -0800 (PST)
X-Received: by 2002:ad4:5f8b:0:b0:6e6:62e0:887b with SMTP id 6a1803df08f44-6e66cd29e70mr149586706d6.45.1739814987028;
        Mon, 17 Feb 2025 09:56:27 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e65d9f46a8sm54068316d6.82.2025.02.17.09.56.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 09:56:26 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <d9c96532-9598-426e-a469-dafd17d47a70@redhat.com>
Date: Mon, 17 Feb 2025 12:56:25 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250217042108.185932-1-longman@redhat.com>
 <CA+fCnZcaLBUUEEUNr8uZqW1dJ8fsHcOGCy3mJttfFDKq=A_9OQ@mail.gmail.com>
In-Reply-To: <CA+fCnZcaLBUUEEUNr8uZqW1dJ8fsHcOGCy3mJttfFDKq=A_9OQ@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: APuN69U8VrI2Zs9fDjRbeXSYPJyZt4EgxDH4ptNoujk_1739814987
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Mdeo+KhA;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 2/17/25 11:28 AM, Andrey Konovalov wrote:
> On Mon, Feb 17, 2025 at 5:21=E2=80=AFAM Waiman Long <longman@redhat.com> =
wrote:
>> The following bug report appeared with a test run in a RT debug kernel.
>>
>> [ 3359.353842] BUG: sleeping function called from invalid context at ker=
nel/locking/spinlock_rt.c:48
>> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 14=
0605, name: kunit_try_catch
>> [ 3359.353853] preempt_count: 1, expected: 0
>>    :
>> [ 3359.353933] Call trace:
>>    :
>> [ 3359.353955]  rt_spin_lock+0x70/0x140
>> [ 3359.353959]  find_vmap_area+0x84/0x168
>> [ 3359.353963]  find_vm_area+0x1c/0x50
>> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
>> [ 3359.353972]  print_report+0x108/0x1f8
>> [ 3359.353976]  kasan_report+0x90/0xc8
>> [ 3359.353980]  __asan_load1+0x60/0x70
>>
>> Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
>> changes report_lock to a raw_spinlock_t to avoid a similar RT problem.
>> The print_address_description() function is called with report_lock
>> acquired and interrupt disabled.  However, the find_vm_area() function
>> still needs to acquire a spinlock_t which becomes a sleeping lock in
>> the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
>> changing report_lock to a raw_spinlock_t is not enough to completely
>> solve this RT kernel problem.
>>
>> Fix this bug report by skipping the find_vm_area() call in this case
>> and just print out the address as is.
>>
>> For !RT kernel, follow the example set in commit 0cce06ba859a
>> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
>> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
>> inside raw_spinlock_t warning.
>>
>> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
>> Signed-off-by: Waiman Long <longman@redhat.com>
>> ---
>>   mm/kasan/report.c | 43 ++++++++++++++++++++++++++++++-------------
>>   1 file changed, 30 insertions(+), 13 deletions(-)
>>
>>   [v3] Rename helper to print_vmalloc_info_set_page.
>>
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 3fe77a360f1c..7c8c2e173aa4 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -370,6 +370,34 @@ static inline bool init_task_stack_addr(const void =
*addr)
>>                          sizeof(init_thread_union.stack));
>>   }
>>
>> +/*
>> + * RT kernel cannot call find_vm_area() in atomic context. For !RT kern=
el,
>> + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-typ=
e
>> + * to WAIT_SLEEP.
> Quoting your response from the other thread:
>
>> Lockdep currently issues warnings for taking spinlock_t inside
>> raw_spinlock_t because it is not allowed in RT. Test coverage of RT
>> kernels is likely less than !RT kernel and so less bug of this kind will
>> be caught. By making !RT doing the same check, we increase coverage.
>> However, we do allow override in the !RT case, but it has to be done on
>> a case-by-case basis.
> Got it.
>
> So let's put this exactly this explanation in the comment, otherwise
> it's unclear why we need something special for the !RT case.

Sure. Will do that.


>> + */
>> +static inline void print_vmalloc_info_set_page(void *addr, struct page =
**ppage)
>> +{
>> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
>> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLE=
EP);
>> +               struct vm_struct *va;
>> +
>> +               lock_map_acquire_try(&vmalloc_map);
>> +               va =3D find_vm_area(addr);
>> +               if (va) {
>> +                       pr_err("The buggy address belongs to the virtual=
 mapping at\n"
>> +                              " [%px, %px) created by:\n"
>> +                              " %pS\n",
>> +                              va->addr, va->addr + va->size, va->caller=
);
>> +                       pr_err("\n");
>> +
>> +                       *ppage =3D vmalloc_to_page(addr);
> Looking at the code again, I actually like the Andrey Ryabinin's
> suggestion from the v1 thread: add a separate function that contains
> an annotated call of find_vm_area(). And keep vmalloc_to_page()
> outside of it, just as done in the upstream version now.

I can make the change if it is what you want.

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
9c96532-9598-426e-a469-dafd17d47a70%40redhat.com.
