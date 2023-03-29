Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXG2SGQQMGQEEEK6U4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A770F6CEFEB
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 18:54:54 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id z4-20020a25bb04000000b00b392ae70300sf16128677ybg.21
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 09:54:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680108892; cv=pass;
        d=google.com; s=arc-20160816;
        b=xZENZ75MZUjrLLLP6ugoIZMiihYAUKaQWQpbeJ1rnNrYfXCp9QyVIwSEVNg6uCsU9r
         BULmFhAFzagBRB56zZwDIoN+TUPIXL+nVhuRPRFyquPGzSwxuysvhvCKOH29d/m5jWGc
         lyhybYiNshpCSKaxVMlI7DxfSPq95tpE0m2FTqn5F2w4+SDjlI0JPXrz71zJGv+czhnH
         NhdOxstqydCDNR8bUQainl7Xy6Pm05uiUXmNLHVmXDhwUHztp1xEy4VSYdFLEoogD6cI
         2zEErcpUOf+/rVt2mkB+Gqt8mLyX9keCkCtFUUSGfy1jDntxbjOM21UKHRI/S65TZmP/
         dcxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pymBTC4el55TdNE9hvi2x8UtH3Jecme2/3NtCrSduO8=;
        b=TNepml/xS6Mabm24juEP2exyB/usCYnx04PLLePyjZ3NtgxiaKBLzYW9nWh0mnnD7D
         yQeZWX1yGtr0gDNPU2UjSYS7yLVduDvgLH6JR9fZ1bkx0O+vF7JzFi61Jp+dqFJnFIyv
         KuAr6AK8JHmofy+kNTkMOZFc3g6GiEzZGOjRwmDdH7zPR9KYwPmnbX9oxq5G/8nb3Noc
         Ju7b8kzs0NDhFl/ChBreCcX5MHrmIx/c1KJ+AyMcEVtt6KK5rtmxsmm3dI+78hpDygcb
         IpqVTECbROGkK0GeZoYEFMBDx//33Ik+/FtgDpYUyt2d9ZowOfcfBb/Evrd94+Qqz+pU
         6+sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680108892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pymBTC4el55TdNE9hvi2x8UtH3Jecme2/3NtCrSduO8=;
        b=mrjp7tMHXQeL5eawWeUR6M5oHTlIggcUM8xzPfSnWU8v19G/ywap1SEGTICGcXNmFq
         C658i1e3vuzM9SjNapScg5ploDzn3exVOtvz/EWDksSqrmI1nndxTsfL495wWcCfaClX
         3veVhEI1lNdKdDj/hFACCdir215J1nsv34OTR2V34QbGacLChzYwcu+98faKWiDdrVaw
         Edtpppix8256LJArvNJrFzbi9BUDWnlupTzU+lMweQ+A3V92QzLNaYGCk6Xz6kN6xra/
         9nzyub6bCK0B72ND9v1j+C8uDosdR6UyWJhZiwU5EX8eHq0h4tE2K/W61UKx9BiP+VKW
         Wijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680108892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pymBTC4el55TdNE9hvi2x8UtH3Jecme2/3NtCrSduO8=;
        b=CWe4Vh0fK5Rp7npPagNpaeaD6E4ZLwRMOgUUBQVB3wicleWSZjaTbXlBEBdR8wvJYo
         OHx0n6OuJnNThNp+nfoxorkKZDJ357dMHqI8DBjjt4YQIu9pAQ7GXb/q3Ki6NQEnTqsL
         WxESbW5Xi8f0qy3Aeny0gqoGOaD5JIT/bHx4Aqv/VM/x2elE5U8A++cQLBIqHV8vFy2B
         /kt1KbP8PPDTg5MY19jV7pGGJQ+5u6NoThc+YDwzz2/eQLNnctLi5X7rOFv6WE2ahp2K
         LfILGQyesis5+kvsEnZT1j5NAJ+YyAYFDiMsfrfHdeCZkMIphQ2qboao5SDZubcSFYpR
         Ji1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dbgAENXn1xO0sTb8Ebv/8zUGp1BHq8OX4KB7CsXMnzdqSzCK8d
	ivmXQsf+Llafmp+nA9L4BVg=
X-Google-Smtp-Source: AKy350ZF2IM9rtc31G3XamBio1sc73sOXGfLkPmYUCu/lGgiTVDO0ZN55Au1/VXsRWUnvZR73VdbEA==
X-Received: by 2002:a81:e308:0:b0:532:e887:2c23 with SMTP id q8-20020a81e308000000b00532e8872c23mr9907804ywl.9.1680108892653;
        Wed, 29 Mar 2023 09:54:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1607:b0:b61:1f9e:bff5 with SMTP id
 bw7-20020a056902160700b00b611f9ebff5ls10295063ybb.11.-pod-prod-gmail; Wed, 29
 Mar 2023 09:54:51 -0700 (PDT)
X-Received: by 2002:a25:b10b:0:b0:b44:b1d0:3e82 with SMTP id g11-20020a25b10b000000b00b44b1d03e82mr21812678ybj.12.1680108891906;
        Wed, 29 Mar 2023 09:54:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680108891; cv=none;
        d=google.com; s=arc-20160816;
        b=zKzlQ2H0bNgRSm3t/T1elmw99CdfIExNtj2VsmEuGRoEwj9iR+bHSpjNOba14CVOX2
         7S38GzWXwMV+iAzfqaNDlrXdnrBEtZI0RUyxKHwnREarBV7KDecFPpao0yxKi+38kIe4
         PXMacOgOUMDnnNJs2tVNWUgdy7Xtt2MpMbGVJJBPxoBY750n3pbf/rtMamSExCbyt497
         /qMEauXA0MAipzQ2rgKa8TXQe2tSxbrGtTp947/3eIpMHi8ZrISWBYpymDlIcAEP6LAi
         mNsqKkXaX6qH/zmXzrcBnhi0QC7GJujhwDeeLiqA7VAJbMW/AlevuestOJdmCVdOmJcC
         LGgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=/aZSZ0es9sTAj0t2pGa0MkaCKs14ZkTxuDWGo71gOwY=;
        b=W6IsiTPAXkowBriP87EvqpJwj2RikyNhvtl52CFz9KIS4NDE7hMiDjHwpa2iEmePyp
         kM74kYmOOjGFqBeU4MhD758U0mxQlJMdg0mxuK7Fghe5DTAROgaRntHQn28bbJEFcgme
         gL4KsdzpXsVr+/D/DvLCIonm8BrG31ZPaRm7ihYeF8GOVTBW98V68tnO/CgHz9od+CHg
         p4x++EuYyGVkxv/fwpY3IFTAUZ+3PEMoZAj3D//WUXSna+6edjWS8tvA+AI5tSK9WrEA
         I8iEBGN4bHY0PO3G5iWu+dy2DuKDXibN/HHTGxJ1ZATkLj/3em7QHhCqiYUwbPjI8ns7
         ymAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id k4-20020a056902070400b00b633f199b9dsi84195ybt.1.2023.03.29.09.54.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Mar 2023 09:54:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 72C6161D85;
	Wed, 29 Mar 2023 16:54:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6E6DC433D2;
	Wed, 29 Mar 2023 16:54:48 +0000 (UTC)
Date: Wed, 29 Mar 2023 17:54:45 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Cc: "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	Steven Price <steven.price@arm.com>
Subject: Re: [BUG] Usersapce MTE error with allocation tag 0 when low on
 memory
Message-ID: <ZCRtVW9Q0WOKEQVX@arm.com>
References: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

+ Steven Price who added the MTE swap support.

On Wed, Mar 29, 2023 at 02:55:49AM +0000, Qun-wei Lin (=E6=9E=97=E7=BE=A4=
=E5=B4=B4) wrote:
> Hi,
>=20
> We meet the mass MTE errors happened in Android T with kernel-6.1.
>=20
> When the system is under memory pressure, the MTE often triggers some
> error reporting in userspace.
>=20
> Like the tombstone below, there are many reports with the acllocation
> tags of 0:
>=20
> Build fingerprint:
> 'alps/vext_k6897v1_64/k6897v1_64:13/TP1A.220624.014/mp2ofp23:userdebug/
> dev-keys'
> Revision: '0'
> ABI: 'arm64'
> Timestamp: 2023-03-14 06:39:40.344251744+0800
> Process uptime: 0s
> Cmdline: /vendor/bin/hw/camerahalserver
> pid: 988, tid: 1395, name: binder:988_3  >>>
> /vendor/bin/hw/camerahalserver <<<
> uid: 1047
> tagged_addr_ctrl: 000000000007fff3 (PR_TAGGED_ADDR_ENABLE,
> PR_MTE_TCF_SYNC, mask 0xfffe)
> signal 11 (SIGSEGV), code 9 (SEGV_MTESERR), fault addr
> 0x0d000075f1d8d7f0
>     x0  00000075018d3fb0  x1  00000000c0306201  x2  00000075018d3ae8  x
> 3  000000000000720c
>     x4  0000000000000000  x5  0000000000000000  x6  00000642000004fe  x
> 7  0000054600000630
>     x8  00000000fffffff2  x9  b34a1094e7e33c3f  x10
> 00000075018d3a80  x11 00000075018d3a50
>     x12 ffffff80ffffffd0  x13 0000061e0000072c  x14
> 0000000000000004  x15 0000000000000000
>     x16 00000077f2dfcd78  x17 00000077da3a8ff0  x18
> 00000075011bc000  x19 0d000075f1d8d898
>     x20 0d000075f1d8d7f0  x21 0d000075f1d8d910  x22
> 0000000000000000  x23 00000000fffffff7
>     x24 00000075018d4000  x25 0000000000000000  x26
> 00000075018d3ff8  x27 00000000000fc000
>     x28 00000000000fe000  x29 00000075018d3b20
>     lr  00000077f2d9f164  sp  00000075018d3ad0  pc  00000077f2d9f134  p
> st 0000000080001000
>=20
> backtrace:
>       #00 pc 000000000005d134  /system/lib64/libbinder.so
> (android::IPCThreadState::talkWithDriver(bool)+244) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #01 pc 000000000005d448  /system/lib64/libbinder.so
> (android::IPCThreadState::getAndExecuteCommand()+24) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #02 pc 000000000005dd64  /system/lib64/libbinder.so
> (android::IPCThreadState::joinThreadPool(bool)+68) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #03 pc 000000000008dba8  /system/lib64/libbinder.so
> (android::PoolThread::threadLoop()+24) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #04 pc 0000000000013440  /system/lib64/libutils.so
> (android::Thread::_threadLoop(void*)+416) (BuildId:
> 10aac5d4a671e4110bc00c9b69d83d8a)
>       #05 pc
> 00000000000c14cc  /apex/com.android.runtime/lib64/bionic/libc.so
> (__pthread_start(void*)+204) (BuildId:
> 718ecc04753b519b0f6289a7a2fcf117)
>       #06 pc
> 0000000000054930  /apex/com.android.runtime/lib64/bionic/libc.so
> (__start_thread+64) (BuildId: 718ecc04753b519b0f6289a7a2fcf117)
>=20
> Memory tags around the fault address (0xd000075f1d8d7f0), one tag per
> 16 bytes:
>       0x75f1d8cf00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d000: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d100: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d200: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d300: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d400: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d500: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d600: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>     =3D>0x75f1d8d700: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 [0]
>       0x75f1d8d800: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d900: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8da00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8db00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8dc00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8dd00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8de00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>=20
> Also happens in coredump.
>=20
> This problem only occurs when ZRAM is enabled, so we think there are
> some issues regarding swap in/out.
>=20
> Having compared the differences between Kernel-5.15 and Kernel-6.1,
> We found the order of swap_free() and set_pte_at() is changed in
> do_swap_page().
>=20
> When fault in, do_swap_page() will call swap_free() first:
> do_swap_page() -> swap_free() -> __swap_entry_free() ->
> free_swap_slot() -> swapcache_free_entries() -> swap_entry_free() ->
> swap_range_free() -> arch_swap_invalidate_page() ->
> mte_invalidate_tags_area() ->  mte_invalidate_tags() -> xa_erase()
>=20
> and then call set_pte_at():
> do_swap_page() -> set_pte_at() -> __set_pte_at() -> mte_sync_tags() ->
> mte_sync_page_tags() -> mte_restore_tags() -> xa_load()
>=20
> This means that the swap slot is invalidated before pte mapping, and
> this will cause the mte tag in XArray to be released before tag
> restore.
>=20
> After I moved swap_free() to the next line of set_pte_at(), the problem
> is disappeared.
>=20
> We suspect that the following patches, which have changed the order, do
> not consider the mte tag restoring in page fault flow:
> https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/
>=20
> Any suggestion is appreciated.
>=20
> Thank you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZCRtVW9Q0WOKEQVX%40arm.com.
