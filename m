Return-Path: <kasan-dev+bncBCY5VBNX2EDRBCW7YLXQKGQE77FOP7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C375111A657
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 09:57:46 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id d8sf10145916wrq.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 00:57:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576054666; cv=pass;
        d=google.com; s=arc-20160816;
        b=G3K6v4p5LtsUm6Qp+5pa47bb8FJ0ArHVo8VU0w7uWPMDIe6U3hCgbEoI5FSTW2plmJ
         wxFSz7JncDj3wuYWG2OljaaiShhOIzFzy5upuroA2/z/D310ES0m2VUYELpYA5bx2nM2
         qB53a3VsialVD3y8pjtw/He39wg1XruiZW0cmKZInbi5vTqnbvkyhMDI0f0VvDgCnQyj
         C1PCOvrRKbceIdgpU3wVJA5wC4QzyxXkPGk/07e0Eany9+rIMIVt9aHmI4dvlZdnVInb
         8fzHKVcHZA9yhWoSv33kkbaza8RQU36EDF44elkh7qXwGxSzHLHCRBIrI9RHpPhln3Uu
         orlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature
         :dkim-signature;
        bh=79KGWg4BMLDsSWQ0yvHHv/m06VlamIZgRJngAedGXjs=;
        b=t72mtIUeGjIHniF7ESxpdq5uY3U5Z2e25+mMb8WjWtvBBQ6PkIX0tbGwqomAIAWXGo
         fOKtDNbWHOS5CHqiWFxKW+Qw/AlwKo95WnqwqoAhFtatsAw4My5uAmL+jdq+JlEa/pOQ
         6UmcChDiCTmvKa6d3qT/t8lKgKyDPFhYZfx9P8ArTfQOuQ4hzyKNJ6xs3RVgnVwNgJj+
         ulZldYbZb8mn0eFSfwVo7u7vTW/skHYSpqFrGWkgySdlg7hGxypvBpGkF6BeMzVFSjvT
         9McXUkVLo4jmwsMK8ulsVJsCOtBHToaSLeHkKmK+K3eo7V3+6pUylcjgOWPp/vFK0m/v
         KJhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uJpx+Q19;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=79KGWg4BMLDsSWQ0yvHHv/m06VlamIZgRJngAedGXjs=;
        b=SK0RbxhVxEvGo+tsvQ9oAZb+wa7JWOItK7jQumfxnIRRZvLDEYm+fqUNanou+zB6pS
         BeuMjXIjmIeY1uongHnXiVPv/SGEdppp251JY0ZKKVHK64ZrS0BAvd19zhVpfsoiNYlk
         r2XQ9HhMw700lNSBuxeVIFXwIjPJ6JMRNjNdvALk5SDAtpOeDP5beyR/dIyZBrQswYL5
         qMv2P4m9nRoiabYZijYEAf9QIWW4KZvA16HDIDr4Rdf+IS+0V/hDX5aOUO5FO9WtjrCL
         FUkqZpmSZ6HHIsHhhdlqPlOm8qelYqK/ZSohI1WQvZjb1K9Uha3nC3xY+Lp3Jo5lSPWI
         eoQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=79KGWg4BMLDsSWQ0yvHHv/m06VlamIZgRJngAedGXjs=;
        b=XfySKtCmGvGY54EGOnNdyNSjpyyoct7QoPGjRb+zR+HPQqd4H+FfO3RaHdUemXNIaC
         YSiQXhZ8HFIbJFyB2rgkB5fbyQKuUAoGuqCoN8pZET/b28rgp6P0Jld65gIglUX8PgRs
         w6jxsKvw8npCSlLafpBlzMcSB6gdc8kTguZpbDqg/gZZsfcku9sdYlyIoXIquKfgnbhD
         k08Hh46Vo5kBI8V6/U/7RzQqEuFH/IM4QwE9WYe7h9XmxSEGswl5MBDMb7IP/dbjelkC
         OptiA1hzxPlwflDGwVTvbkLDIYlaTJp0S/y5GL54DYpT1HWKraQ+Up5hUqkna8vghzMs
         +BVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=79KGWg4BMLDsSWQ0yvHHv/m06VlamIZgRJngAedGXjs=;
        b=jZkdrsgS1N6QmLrJz9WG1MGqSRLJD+qZjgzfvPH81ZmGWPQPZImjJ6FWfZ0Fsdx/m6
         gVFCpklwoW3cqFi+5VySeUN1sRqKkH8tOlHnnSlD3uZ2MGvoI8jvEdip6sof4s05iyKm
         WMStncnG+zf6Y2SlJXJADgSgeTv0jcr933XKfRO+4OfEiH6vzQhMMSYEwiWYkVpRT990
         GPFvi3p4u0IlXcX1o4FAciZA558m1Iq0U01GERO7sDMtPUaYsyoWckfqj5hW4yBIcvNY
         BHC7vLfyr4Q/iwO6YYjeFnj5MPUsTwiCOET+IjskMLczRh6QwbTF0extH0MyC7WsZ2NI
         0eFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdP07bFKUoG0K34M5c3E754A/zBO1r8uxpVyGGT82ZoXkqwpuh
	lRsQHdeN3Hi1ZeSOfw7D2H4=
X-Google-Smtp-Source: APXvYqxE3l21BR+q0PlOhY0Dsw6H1bGNQ2PkOwXvdqA2YpbGOdRwaUICwy3QR9yYGB/Qj3LoDJuE9w==
X-Received: by 2002:a7b:c85a:: with SMTP id c26mr2267731wml.107.1576054666386;
        Wed, 11 Dec 2019 00:57:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf15:: with SMTP id l21ls1126094wmg.0.canary-gmail; Wed,
 11 Dec 2019 00:57:45 -0800 (PST)
X-Received: by 2002:a7b:ce19:: with SMTP id m25mr2364803wmc.6.1576054665830;
        Wed, 11 Dec 2019 00:57:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576054665; cv=none;
        d=google.com; s=arc-20160816;
        b=RoqTk8ayEURYEWsKORnsBDSjhVRe5ar5h7MyhRxidhcBKZnkbSuLJ4ZY3zyTBW44OW
         rR1ASwtqsc/a4gZ/IDcXcXkYJn98RacbzFF9TynwGhIFBRd/hr6dHiMv9tWN+SblC9cW
         Bm5PTtKS3ZiUVCEGN0sUJxqRi77C39/wNmNkpYVJkRGqMb7qLnHihyNBcDBcYPP9DlGT
         htwlc+LLRPd7YvRG1l2uZ3vh2ckUeF4uailOn8LnV+g+9b25duPDLAXEQQujrubLP0y0
         hwIdu7Qv2ED5RTwm7n/qemZyske7Ty4WlfM4ae7AGivqKYnGqpP+44fZ8uKz3nRmXzbn
         13xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=bIfbFzQT9ZxQ4e4nrVfDT9ML1R0zmGFtDVqaemsabhc=;
        b=LkoGRdxzjz90zsvgCCU4v/JhNYxXTzG4fulEandXMt66i24eLwcvqly7ruze0DIPBp
         JPJsBGzAMYA5uaA2SHu6/w1jEfsKMehYnqmyWtj6y1vb1p4HPWpmCI4qqyJW9SzNyBHi
         s/6AZQDdlk1tYx7Hsi1M6FDWPYj5x9NPjt4XLa99GjIeCW4QOeYV8YpXiD7ynDEAkFpK
         tAohPwuM1bt/iFlvNRAietW6vIXI7BTMq+Twf3xJmvPvVfUHv9K7oPejT1rjF7biC0aQ
         cFZdyZr8N+dJ+iadCVUJg19sfkmnssy/589JLCyGTGVXVoz+rj4KnCCBOSxI9lkpyVVJ
         /OxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uJpx+Q19;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id r11si68837wrl.3.2019.12.11.00.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 00:57:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id p17so6068588wmi.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 00:57:45 -0800 (PST)
X-Received: by 2002:a7b:cd0a:: with SMTP id f10mr2377880wmj.111.1576054665197;
        Wed, 11 Dec 2019 00:57:45 -0800 (PST)
Received: from [192.168.68.108] (115-64-122-209.tpgi.com.au. [115.64.122.209])
        by smtp.gmail.com with ESMTPSA id q6sm1513859wrx.72.2019.12.11.00.57.39
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 00:57:44 -0800 (PST)
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-5-dja@axtens.net>
 <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
 <875zincu8a.fsf@dja-thinkpad.axtens.net>
From: Balbir Singh <bsingharora@gmail.com>
Message-ID: <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
Date: Wed, 11 Dec 2019 19:57:34 +1100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <875zincu8a.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=uJpx+Q19;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::341
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 11/12/19 4:21 pm, Daniel Axtens wrote:
> Hi Balbir,
>=20
>>> +Discontiguous memory can occur when you have a machine with memory spr=
ead
>>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>>> +
>>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>>> + - then there's a gap,
>>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_=
0000_0000
>>> +
>>> +This can create _significant_ issues:
>>> +
>>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, =
we would
>>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserv=
e the
>>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the =
shadow
>>> +   region. But when we try to access any of that, we'll try to access =
pages
>>> +   that are not physically present.
>>> +
>>
>> If we reserved memory for KASAN from each node (discontig region), we mi=
ght survive
>> this no? May be we need NUMA aware KASAN? That might be a generic change=
, just thinking
>> out loud.
>=20
> The challenge is that - AIUI - in inline instrumentation, the compiler
> doesn't generate calls to things like __asan_loadN and
> __asan_storeN. Instead it uses -fasan-shadow-offset to compute the
> checks, and only calls the __asan_report* family of functions if it
> detects an issue. This also matches what I can observe with objdump
> across outline and inline instrumentation settings.
>=20
> This means that for this sort of thing to work we would need to either
> drop back to out-of-line calls, or teach the compiler how to use a
> nonlinear, NUMA aware mem-to-shadow mapping.

Yes, out of line is expensive, but seems to work well for all use cases.
BTW, the current set of patches just hang if I try to make the default
mode as out of line


>=20
> I'll document this a bit better in the next spin.
>=20
>>> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
>>> +		kasan_memory_size =3D
>>> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
>>> +
>>> +		if (top_phys_addr < kasan_memory_size) {
>>> +			/*
>>> +			 * We are doomed. Attempts to call e.g. panic() are
>>> +			 * likely to fail because they call out into
>>> +			 * instrumented code, which will almost certainly
>>> +			 * access memory beyond the end of physical
>>> +			 * memory. Hang here so that at least the NIP points
>>> +			 * somewhere that will help you debug it if you look at
>>> +			 * it in qemu.
>>> +			 */
>>> +			while (true)
>>> +				;
>>
>> Again with the right hooks in check_memory_region_inline() these are rec=
overable,
>> or so I think
>=20
> So unless I misunderstand the circumstances in which
> check_memory_region_inline is used, this isn't going to help with inline
> instrumentation.
>=20

Yes, I understand. Same as above?


>>> +void __init kasan_init(void)
>>> +{
>>> +	int i;
>>> +	void *k_start =3D kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
>>> +	void *k_end =3D kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
>>> +
>>> +	pte_t pte =3D __pte(__pa(kasan_early_shadow_page) |
>>> +			  pgprot_val(PAGE_KERNEL) | _PAGE_PTE);
>>> +
>>> +	if (!early_radix_enabled())
>>> +		panic("KASAN requires radix!");
>>> +
>>
>> I think this is avoidable, we could use a static key for disabling kasan=
 in
>> the generic code. I wonder what happens if someone tries to boot this
>> image on a Power8 box and keeps panic'ing with no easy way of recovering=
.
>=20
> Again, assuming I understand correctly that the compiler generates raw
> IR->asm for these checks rather than calling out to a function, then I
> don't think we get a way to intercept those checks. It's too late to do
> anything at the __asan report stage because that will already have
> accessed memory that's not set up properly.
>=20
> If you try to boot this on a Power8 box it will panic and you'll have to
> boot into another kernel from the bootloader. I don't think it's
> avoidable without disabling inline instrumentation, but I'd love to be
> proven wrong.
>=20
>>
>> NOTE: I can't test any of these, well may be with qemu, let me see if I =
can spin
>> the series and provide more feedback
>=20
> It's actually super easy to do simple boot tests with qemu, it works fine=
 in TCG,
> Michael's wiki page at
> https://github.com/linuxppc/wiki/wiki/Booting-with-Qemu is very helpful.
>=20
> I did this a lot in development.
>=20
> My full commandline, fwiw, is:
>=20
> qemu-system-ppc64  -m 8G -M pseries -cpu power9  -kernel ../out-3s-radix/=
vmlinux  -nographic -chardev stdio,id=3Dcharserial0,mux=3Don -device spapr-=
vty,chardev=3Dcharserial0,reg=3D0x30000000 -initrd ./rootfs-le.cpio.xz -mon=
 chardev=3Dcharserial0,mode=3Dreadline -nodefaults -smp 4

qemu has been crashing with KASAN enabled/ both inline/out-of-line options.=
 I am running linux-next + the 4 patches you've posted. In one case I get a=
 panic and a hang in the other. I can confirm that when I disable KASAN, th=
e issue disappears

Balbir Singh.

>=20
> Regards,
> Daniel
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2e0f21e6-7552-815b-1bf3-b54b0fc5caa9%40gmail.com.
