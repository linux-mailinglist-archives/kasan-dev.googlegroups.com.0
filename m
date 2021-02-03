Return-Path: <kasan-dev+bncBCW7LPVNTAKBB7HS5OAAMGQEZR75FLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CBB5430E33B
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 20:29:01 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 44sf391382otc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 11:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612380540; cv=pass;
        d=google.com; s=arc-20160816;
        b=gGIbs5Bc8oNA4tPzsCrT3ednLup1L513mSTX4lTrUMFjpNrtyNUNVckl45RjpBZLOq
         g0wjmksH6nADqKkqiFvPwavvZSvXv9RcPKshDD+zaz3Ip8kchp2CpE6PxaT24FzhzG7T
         FugapK9vNGAECRDW6NqekO4UuMRYNxyayOw8TCTiYLCbZbanv1ettlviDjgyLKjedKGV
         ic5Z8WDQ5swoOfAZqQ9wIXgK59Sc73OP7ntHq5seYrqRPcQ64ePr/p2VEXC21ZkOh6no
         PJIksjNjbD6hFo8dplcmPzBA5bgaoNzxAk45zuf12ZA/WYW8Ju9I9pn7bLKAinQoHSbM
         kyBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Jg80quCdSTWo8Fk0/o2IL/S8S3UQX2joKSecG4kq0k8=;
        b=eIl7mAhq4L+RzKNL8/Pm9AysMcdsocjI+oM+kgjl9cczz+JtZ1qSrfzcm25v2cIz/c
         nlD4USMbPD9EHQD7Fs9nKaiWji/JD6eCVLC+0H3Bl76jlDQcPNP71eEAMGXwpcbO4G5j
         xKBTkutPsDGK3qQaK7JdvpvIjkxptP+0SfDzB+GG6pvHffuCUpSq0e4TuJRCLJPacvhi
         Bc8fDxK8TKWLyeF2tzNcSe83yz3E75oyYRMvwcGXmgLGevxxQdfn0FwwQU9ephlkcXk1
         791RAUw3JVBEm0Q45CBl3atOEEIgXKO4NdCKPfF5Dra/cZQsEPi8siO/1saBolW0gg/g
         oaWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gYSgK0gI;
       spf=pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Jg80quCdSTWo8Fk0/o2IL/S8S3UQX2joKSecG4kq0k8=;
        b=QMyYL6J974ckjCv8uCPmE/rES3NrQcFrr2WycD6TVMKYy9gvyhMbblVDj/ZEJo3tvU
         C7j24dFWVS/qaRfdK3S2SpvklVgz/PurSO6zawxuaPtxXN2cdAiWPSFVRLkWT0vhiklQ
         9OBelIxmU7OzuYCBFSASGBRYAUuJLb2R7CdmYw8laUme915Px+fWIekLBl+spqRDoQpj
         0O0JhjRGAU+6bS8/PN0YePdH6DDpbOQz/AaVGtIg36lKrSLEYOhRi2u/KrQOfdNEzGsL
         DUumeOXg07tfGfD21lUfDF771S0MJh0yoTZjIIyHTdqbwhL+K1/nFTluMzmW9PM3JoGN
         djtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jg80quCdSTWo8Fk0/o2IL/S8S3UQX2joKSecG4kq0k8=;
        b=XkBrP1cMQd2kt0GWvhitqqWuhrgioJbtqkC5Y6fk1S3VsyyDc6ck6Ev6nv06z5iFqn
         WVI6+eZxJuCDtGma0271coXhkgC+rebHcP3ajcvXbUxXjb3r/Mrw4/aXJPi4YKE+MZp3
         jMovaVNDG1VniN7vl5vlNq1vGRegIERdxfvMhpAJQaDheDEynMgDJN6UUUu9gh/NZ+Ye
         sXlpTHfgWU8yBvmcbJtdYfSbLnZcGaXbaj4hSiAd2IgagiNVjMzpJDopHj8+qnyasKco
         8XS3oR3VG7ifjJAVV7tMGrR4D0+/pwNa/1c4EXSISGZA73fBlYZdjpcAzpm/0NFDuhYc
         Zxgw==
X-Gm-Message-State: AOAM530X+4l7LngqMlMhH+YlntW/hA8mZfSTg2QaVTVqvRx3J1yuLIR8
	NT/CVXfYOFxSodv94refUM4=
X-Google-Smtp-Source: ABdhPJwHBx9xM3dtvdGZRw9ZE7oHC3SvIoc5S+QR7UzX6MKsf0mvsXdPNWxZyxEfxrjea7P8OMptTQ==
X-Received: by 2002:a4a:8555:: with SMTP id l21mr3183308ooh.27.1612380540801;
        Wed, 03 Feb 2021 11:29:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cc51:: with SMTP id c78ls799823oig.5.gmail; Wed, 03 Feb
 2021 11:29:00 -0800 (PST)
X-Received: by 2002:aca:f510:: with SMTP id t16mr3031300oih.141.1612380540196;
        Wed, 03 Feb 2021 11:29:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612380540; cv=none;
        d=google.com; s=arc-20160816;
        b=ENZ+MBwFaT8D0hETuMYC7fuBtf2gbfPiyV6TBYl0L5ymmMwobshxMPbAcA1sVADdtJ
         2J2UMNINVUbnG4Q/2l9caKiiTFvqrap1bLj47mHeALd6rSzcXfZVxGaiUZOG1WVu9odR
         VjXKUnYSy69K5LGKVmVL9pgfNu36D9xsqOTm85X4vHv+4+StGy8bTUJv/1LKf4gL+enZ
         GYsj8jaW6UgdwiHTxNPkebsDHfzTgb9d21liMyRvxa0iV0tpO1kOgu1fWAT8GvIJpGoo
         aptN8SnTZrt5BSJ4YsS8iFE3tTZZ9vtzDW8fl434ARW8i0Epq8LOO5vjUnYh+PCtb8Jj
         R8/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Bmms0fzvUjR75dfmgs0kGwS6rjCbP/52m4So/y4HVvM=;
        b=oUGT9Lf4gTDDLD77yIhMdtsgUdxnkF5Kijl2JnZMxpCxZdoQWhpLdRPzo2oK5qab8i
         EGa+3ZfQBIWn7ELPcCChKGle7koDmycX9ObG2uMi/kiXh/2lJ6Rs8j/4KQyicArMTXYe
         vpFkS3LfD+KpAJCQvgnUdsMDZbLLzmdF1Z0GzElTDPE0I8EXSjAz515vRK0+pU3q9Rux
         5DLKAUv2Fncz3jRNx6APg86SJwc5wXYp/n73fII5vhAp1FP++iGCuGSUCE2FAx2MTJYe
         YgaFzjEGUqUwOpXJK/n0nQDKpJ393NriwJzbalsHaI7vfVdHLsJLaiq/YMKBHNJGOwKa
         UmcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gYSgK0gI;
       spf=pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id l126si224367oih.3.2021.02.03.11.29.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 11:29:00 -0800 (PST)
Received-SPF: pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id r77so845696qka.12
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 11:29:00 -0800 (PST)
X-Received: by 2002:a37:d03:: with SMTP id 3mr4229514qkn.45.1612380539669;
        Wed, 03 Feb 2021 11:28:59 -0800 (PST)
Received: from fedora (209-6-208-110.s8556.c3-0.smr-cbr2.sbo-smr.ma.cable.rcncustomer.com. [209.6.208.110])
        by smtp.gmail.com with ESMTPSA id w91sm2165236qte.83.2021.02.03.11.28.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 11:28:58 -0800 (PST)
Sender: Konrad Rzeszutek Wilk <konrad.r.wilk@gmail.com>
Date: Wed, 3 Feb 2021 14:28:56 -0500
From: Konrad Rzeszutek Wilk <konrad@darnok.org>
To: Dmitry Vyukov <dvyukov@google.com>, rjw@rjwysocki.net
Cc: George Kennedy <george.kennedy@oracle.com>,
	Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com,
	konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
Message-ID: <20210203192856.GA324708@fedora>
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
 <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com>
 <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
X-Original-Sender: konrad@darnok.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gYSgK0gI;       spf=pass
 (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::72c
 as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
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

Hey Dmitry, Rafael, George, please see below..

On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
> On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
> <george.kennedy@oracle.com> wrote:
> >
> > Hi Dmitry,
> >
> > On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
> >
> > On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
> > <konrad.wilk@oracle.com> wrote:
> >
> > On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
> >
> > During boot of kernel with CONFIG_KASAN the following KASAN false
> > positive failure will occur when ibft_init() reads the
> > ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
> >
> > The ACPI iBFT table is not allocated, and the iscsi driver uses
> > a pointer to it to calculate checksum, etc. KASAN complains
> > about this pointer with use-after-free, which this is not.
> >
> > Andrey, Alexander, Dmitry,
> >
> > I think this is the right way for this, but was wondering if you have
> > other suggestions?
> >
> > Thanks!
> >
> > Hi George, Konrad,
> >
> > Please provide a sample KASAN report and kernel version to match line numbers.
> >
> > 5.4.17-2102.200.0.0.20210106_0000
> >
> > [   24.413536] iBFT detected.
> > [   24.414074]
> > ==================================================================
> > [   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
> > [   24.407342] Read of size 4 at addr ffff8880be452004 by task swapper/0/1
> > [   24.407342]
> > [   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> > [   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
> > [   24.407342] Call Trace:
> > [   24.407342]  dump_stack+0xd4/0x119
> > [   24.407342]  ? ibft_init+0x134/0xb8b
> > [   24.407342]  print_address_description.constprop.6+0x20/0x220
> > [   24.407342]  ? ibft_init+0x134/0xb8b
> > [   24.407342]  ? ibft_init+0x134/0xb8b
> > [   24.407342]  __kasan_report.cold.9+0x37/0x77
> > [   24.407342]  ? ibft_init+0x134/0xb8b
> > [   24.407342]  kasan_report+0x14/0x1b
> > [   24.407342]  __asan_report_load_n_noabort+0xf/0x11
> > [   24.407342]  ibft_init+0x134/0xb8b
> > [   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
> > [   24.407342]  ? dmi_walk+0x72/0x89
> > [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> > [   24.407342]  ? rvt_init_port+0x110/0x101
> > [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> > [   24.407342]  do_one_initcall+0xc3/0x44d
> > [   24.407342]  ? perf_trace_initcall_level+0x410/0x405
> > [   24.407342]  kernel_init_freeable+0x551/0x673
> > [   24.407342]  ? start_kernel+0x94b/0x94b
> > [   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> > [   24.407342]  ? __kasan_check_write+0x14/0x16
> > [   24.407342]  ? rest_init+0xe6/0xe6
> > [   24.407342]  kernel_init+0x16/0x1bd
> > [   24.407342]  ? rest_init+0xe6/0xe6
> > [   24.407342]  ret_from_fork+0x2b/0x36
> > [   24.407342]
> > [   24.407342] The buggy address belongs to the page:
> > [   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0 mapping:0000000000000000 index:0x1
> > [   24.407342] flags: 0xfffffc0000000()
> > [   24.407342] raw: 000fffffc0000000 ffffea0002fca588 ffffea0002fb1a88 0000000000000000
> > [   24.407342] raw: 0000000000000001 0000000000000000 00000000ffffffff 0000000000000000
> > [   24.407342] page dumped because: kasan: bad access detected
> > [   24.407342]
> > [   24.407342] Memory state around the buggy address:
> > [   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > [   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > [   24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > [   24.407342]                    ^
> > [   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > [   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > [   24.407342]
> > ==================================================================
> > [   24.407342] Disabling lock debugging due to kernel taint
> > [   24.451021] Kernel panic - not syncing: panic_on_warn set ...
> > [   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G    B 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> > [   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
> > [   24.452002] Call Trace:
> > [   24.452002]  dump_stack+0xd4/0x119
> > [   24.452002]  ? ibft_init+0x102/0xb8b
> > [   24.452002]  panic+0x28f/0x6e0
> > [   24.452002]  ? __warn_printk+0xe0/0xe0
> > [   24.452002]  ? ibft_init+0x134/0xb8b
> > [   24.452002]  ? add_taint+0x68/0xb3
> > [   24.452002]  ? add_taint+0x68/0xb3
> > [   24.452002]  ? ibft_init+0x134/0xb8b
> > [   24.452002]  ? ibft_init+0x134/0xb8b
> > [   24.452002]  end_report+0x4c/0x54
> > [   24.452002]  __kasan_report.cold.9+0x55/0x77
> > [   24.452002]  ? ibft_init+0x134/0xb8b
> > [   24.452002]  kasan_report+0x14/0x1b
> > [   24.452002]  __asan_report_load_n_noabort+0xf/0x11
> > [   24.452002]  ibft_init+0x134/0xb8b
> > [   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
> > [   24.452002]  ? dmi_walk+0x72/0x89
> > [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> > [   24.452002]  ? rvt_init_port+0x110/0x101
> > [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> > [   24.452002]  do_one_initcall+0xc3/0x44d
> > [   24.452002]  ? perf_trace_initcall_level+0x410/0x405
> > [   24.452002]  kernel_init_freeable+0x551/0x673
> > [   24.452002]  ? start_kernel+0x94b/0x94b
> > [   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> > [   24.452002]  ? __kasan_check_write+0x14/0x16
> > [   24.452002]  ? rest_init+0xe6/0xe6
> > [   24.452002]  kernel_init+0x16/0x1bd
> > [   24.452002]  ? rest_init+0xe6/0xe6
> > [   24.452002]  ret_from_fork+0x2b/0x36
> > [   24.452002] Dumping ftrace buffer:
> > [   24.452002] ---------------------------------
> > [   24.452002] swapper/-1         1.... 24564337us : rdmaip_init: 2924: rdmaip_init: Active Bonding is DISABLED
> > [   24.452002] ---------------------------------
> > [   24.452002] Kernel Offset: disabled
> > [   24.452002] Rebooting in 1 seconds..
> >
> > Why does KASAN think the address is freed? For that to happen that
> > memory should have been freed. I don't remember any similar false
> > positives from KASAN, so this looks a bit suspicious.
> >
> > I'm not sure why KASAN thinks the address is freed. There are other modules where KASAN/KCOV is disabled on boot.
> > Could this be for a similar reason?
> 
> Most of these files are disabled because they cause recursion in
> instrumentation, or execute too early in bootstrap process (before
> kasan_init).
> 
> Somehow the table pointer in ibft_init points to a freed page. I
> tracked it down to here:
> https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica/tbutils.c#L399
> but I can't find where this table_desc->pointer comes from. Perhaps it

It is what the BIOS generated. It usually points to some memory
location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
other tables in there.

> uses some allocation method that's not supported by KASAN? However,
> it's the only such case that I've seen, so it's a bit weird. Could it
> use something like memblock_alloc? Or maybe that page was in fact
> freed?... Too bad KASAN does not print free stack for pages, maybe
> it's not too hard to do if CONFIG_PAGE_OWNER is enabled...

Hm, there is a comment in the acpi_get_table speaking about the
requirement of having a acpi_put_table and:


 * DESCRIPTION: Finds and verifies an ACPI table. Table must be in the
 *              RSDT/XSDT.
 *              Note that an early stage acpi_get_table() call must be paired
 *              with an early stage acpi_put_table() call. otherwise the table
 *              pointer mapped by the early stage mapping implementation may be
 *              erroneously unmapped by the late stage unmapping implementation
 *              in an acpi_put_table() invoked during the late stage.
 *

Which would imply that I should use acpi_put_table in the error path
(see below a patch), but also copy the structure instead of depending
on ACPI keeping it mapped for me. I think.

CC-ing Rafeal.


From c37da50fdfc62cd4f7b23562b55661478c90a17d Mon Sep 17 00:00:00 2001
From: Konrad Rzeszutek Wilk <konrad@darnok.org>
Date: Tue, 2 Feb 2021 17:28:28 +0000
Subject: [PATCH] ibft: Put ibft_addr back

Signed-off-by: Konrad Rzeszutek Wilk <konrad@darnok.org>
---
 drivers/firmware/iscsi_ibft.c | 19 +++++++++++++------
 1 file changed, 13 insertions(+), 6 deletions(-)

diff --git a/drivers/firmware/iscsi_ibft.c b/drivers/firmware/iscsi_ibft.c
index 7127a04..2a1a033 100644
--- a/drivers/firmware/iscsi_ibft.c
+++ b/drivers/firmware/iscsi_ibft.c
@@ -811,6 +811,10 @@ static void ibft_cleanup(void)
 		ibft_unregister();
 		iscsi_boot_destroy_kset(boot_kset);
 	}
+	if (ibft_addr) {
+		acpi_put_table((struct acpi_table_header *)ibft_addr);
+		ibft_addr = NULL;
+	}
 }
 
 static void __exit ibft_exit(void)
@@ -835,13 +839,15 @@ static void __init acpi_find_ibft_region(void)
 {
 	int i;
 	struct acpi_table_header *table = NULL;
+	acpi_status status;
 
 	if (acpi_disabled)
 		return;
 
 	for (i = 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
-		acpi_get_table(ibft_signs[i].sign, 0, &table);
-		ibft_addr = (struct acpi_table_ibft *)table;
+		status = acpi_get_table(ibft_signs[i].sign, 0, &table);
+		if (ACPI_SUCCESS(status))
+			ibft_addr = (struct acpi_table_ibft *)table;
 	}
 }
 #else
@@ -870,12 +876,13 @@ static int __init ibft_init(void)
 
 		rc = ibft_check_device();
 		if (rc)
-			return rc;
+			goto out_free;
 
 		boot_kset = iscsi_boot_create_kset("ibft");
-		if (!boot_kset)
-			return -ENOMEM;
-
+		if (!boot_kset) {
+			rc = -ENOMEM;
+			goto out_free;
+		}
 		/* Scan the IBFT for data and register the kobjects. */
 		rc = ibft_register_kobjects(ibft_addr);
 		if (rc)
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203192856.GA324708%40fedora.
