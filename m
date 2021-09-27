Return-Path: <kasan-dev+bncBCSJ7B6JQALRBL5PZGFAMGQEAZCKCXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71D0541A3E3
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 01:45:52 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id 6-20020ab00406000000b002c811b109b7sf10973935uav.13
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 16:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632786351; cv=pass;
        d=google.com; s=arc-20160816;
        b=RyU8KVUNtodeh6XhqjRL3RhMWHqjK5yVmNqVD8MKLLyptyv/i3LUtaqKkMA8XVU4DN
         aXHvWkZp1h0R+7C0Fb9tqMbIpvnkhfUW4xYHFMHQwCUDgswnol+mHaWwAkFeszaRMft8
         V6GWV86vLYJpTIRl0G4I1HqTr43rTu/UxhtWzmQX3q3LvcGO4kGP50Sq7ljejZOhHDsE
         U5dqjHL6zeflII015ftwVHs46ilw7MYE4LzOX3ZNbgGw869ifJZJaQpyR4na6fz6miWE
         4rb1ygZclsClj2WS7+yp2uSDSOSf8vy76i53T8yBVOAAJXD5qrMSlK97EvJQOswkUEul
         rzKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H6uW8SI2aPC/xakAvHvWAAV2sBJL2YYp5zxPnq6ZHO4=;
        b=n9M+hGCxvJnmPpkLdiQ9uhGDRDx7ZpVGqZpGgerc+lQGyMlxmWO3xdx7lmkaAutwB9
         B4JzpQyDX5Kr9E4bWNmdcOdI4EBKyrtV+MTVDLX3BZgNsvfVf6mmHTj5n4E7NyDQ0k2R
         4Eb6dYHLtvAODpB3vFwCDCZXwTReRoca2oNPjoBCDwqXBEet/B0L1r6MooPjxNtwlCrN
         m4D80Zt0wgwp4d1j26bT0pZG4f5mDIYFURcdPRprcjfDfZlXy0gFb/RPkTLge1QKJdKP
         hACJ+g4heTSBb4xvIfl5GIJ+VrpXdJ9vIPnnYMJP6TYaNQEITUy6uN1ASr+qvsQJWRQz
         3bvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="MODg/siz";
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H6uW8SI2aPC/xakAvHvWAAV2sBJL2YYp5zxPnq6ZHO4=;
        b=I4sDPGiTTjTXXR5rOBZGwUjt/x4LRPCA9U97S847CwwwqFAeNy37p3hn2oyMV1PvfC
         9t0nK1e2qgPRWymIbmwJdUeEatgurygEIZl72KtlCKLL/T0piyUiR3rpMm/ONHHSotfP
         Ow5k6rG6UqcV1yaUhaeP7zjC/yh2E9KK+Dtdw91CMwmdwLjk3mNDKHyQ4BVMMR7A3YGI
         VmGVGR/UD4c4w+JRo65UilcTAcptkuLYgGimSym2w/7D2F3IFbddKoQfClKGgaZlslie
         gZHvm2B6gCuaBHXMvvSPjagrAvMb5MUiMox8J/gFtRpwb+2CD6oj8dUEaySs5jPX91L3
         tCmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H6uW8SI2aPC/xakAvHvWAAV2sBJL2YYp5zxPnq6ZHO4=;
        b=CU5+/CQu1UzfZEO2SH84WVHbe091EHGqKNd1TLEso+/9WxQu/uQkizGMicejyy9ib2
         IatM1lXXfcDJZeWUP+4+p5Ro+cEbOIrAcGrmdCJ7MBhtlvhtWCg0wVYRzeDPKLWkt98n
         LUN9jvw8WrUTri2uzJfcTcwjojGLyyb6Z5j6B3wuoSO2XgXUWlgyz049vvVI9++5bYLO
         G9UFtK8FnOmmGZTBGRzGRc+8JbRNz2s2INhH3dOrVC6Nit6hdJlcqZ6lTe56bnfWBtFS
         A/IkVIoGyrpIbFedlnr+T/pHCI8F4d9taujLOSVYO1B3vcBsBZ7pEnu/lCOXJeC6Vu93
         UxUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kPikycaqbAMGWhP7Kpi6c0QcoQJtz9aaxFC78/AbSObMmyDf0
	CHOu/1LrirZ3E00tn4Mu4Zo=
X-Google-Smtp-Source: ABdhPJwXP6ogr7UJ3qNYcHl7tznL6YixcM8KfazYz6nXge4yYEhegjgS3V+zyjXJTsecpsk6S4ZvAw==
X-Received: by 2002:ab0:5448:: with SMTP id o8mr2613777uaa.59.1632786351400;
        Mon, 27 Sep 2021 16:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:34d8:: with SMTP id a24ls909515vst.0.gmail; Mon, 27
 Sep 2021 16:45:49 -0700 (PDT)
X-Received: by 2002:a05:6102:34c8:: with SMTP id a8mr2275706vst.21.1632786349545;
        Mon, 27 Sep 2021 16:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632786349; cv=none;
        d=google.com; s=arc-20160816;
        b=mUUrfvoWTuper+doRFyxutARAWstHxihIJxTgAaYMFJSsjGf9YbYAZUMlGVfSMqOMQ
         GyRVC4ogRs/nDKeQUWeR8lgu3hEZsaZRIWOVi7TloT8rrIz03zXoWxWGyetWQ/ahTcvW
         mAGOPek21DXhcyDiaBg4vMLNx+KCtRgIaaEkZ2g4nZb0dD16DIcH0UUVeSwXZCV6wetT
         q/PzwnlDmgKOHycBpcn3B9u0SZBnw3ljTAxoD/2td5gaNVpVnwF32bbENmTY699h4/yK
         +IOt/9JBC/X0oxt/2pdebBf8A1KrY4X4B6a2Mr7UqEjM4JdFEmVkzafKUcAk75CsUDl3
         iNLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nsnSPMX2S/Qat0JZTZ1IQ/fql2yzNENw+yYwIO5gmA8=;
        b=zmSbQorEzIsRzpTHIdqNRUfpW1nxTcB1dclu1XYB6xDqnIVNS58vA+uW603m/CZSuG
         JCoh3syus0EtiSuxTNdc4rUn+lq4G725ihnitIFQ0c2wUWvjgLH8k/mUvHYOKIoycJwX
         xP631CL5f1oaEmiAayMx2/PpgwYSOpDuqWT7/QK74nC8g6IfCb85CWgPHDEGoOiS+W5U
         2AZu1aPOTzHcNM622+pWujGKJWRgWnf57iJl+4//bB7TlaHNe11F9NHkvFaNHVUI+JQr
         euxDnFiBkqC87/3A9xmvF/MvL/VLQ4nLjZ+VNV/ynLuiIeQYh9OM0lLFUmiP3IngOzbo
         lViQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="MODg/siz";
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e8si2219188uaf.0.2021.09.27.16.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Sep 2021 16:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-oo1-f71.google.com (mail-oo1-f71.google.com
 [209.85.161.71]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-172-3ZMxWcDoNI-gagjUtJOM3w-1; Mon, 27 Sep 2021 19:45:47 -0400
X-MC-Unique: 3ZMxWcDoNI-gagjUtJOM3w-1
Received: by mail-oo1-f71.google.com with SMTP id h6-20020a4ae8c6000000b002adb82e3332so17579825ooe.16
        for <kasan-dev@googlegroups.com>; Mon, 27 Sep 2021 16:45:47 -0700 (PDT)
X-Received: by 2002:a05:6830:246f:: with SMTP id x47mr2385800otr.287.1632786346784;
        Mon, 27 Sep 2021 16:45:46 -0700 (PDT)
X-Received: by 2002:a05:6830:246f:: with SMTP id x47mr2385776otr.287.1632786346571;
        Mon, 27 Sep 2021 16:45:46 -0700 (PDT)
Received: from treble ([2600:1700:6e32:6c00::15])
        by smtp.gmail.com with ESMTPSA id o62sm434028ota.14.2021.09.27.16.45.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Sep 2021 16:45:46 -0700 (PDT)
Date: Mon, 27 Sep 2021 16:45:43 -0700
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Sean Christopherson <seanjc@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	the arch/x86 maintainers <x86@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in
 kvm_fastop_exception
Message-ID: <20210927234543.6waods7rraxseind@treble>
References: <000000000000d6b66705cb2fffd4@google.com>
 <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
 <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
 <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com>
 <YUpr8Vu8xqCDwkE8@google.com>
 <CACT4Y+YuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R=DA@mail.gmail.com>
 <YVHsV+o7Ez/+arUp@google.com>
MIME-Version: 1.0
In-Reply-To: <YVHsV+o7Ez/+arUp@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="MODg/siz";
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Mon, Sep 27, 2021 at 04:07:51PM +0000, Sean Christopherson wrote:
> I was asking about the exact location to confirm that the explosion is indeed
> from exception fixup, which is the "unwinder scenario get confused" I was thinking
> of.  Based on the disassembly from syzbot, that does indeed appear to be the case
> here, i.e. this
> 
>   2a:   4c 8b 21                mov    (%rcx),%r12
> 
> is from exception fixup from somewhere in __d_lookup (can't tell exactly what
> it's from, maybe KASAN?).
> 
> > Is there more info on this "the unwinder gets confused"? Bug filed
> > somewhere or an email thread? Is it on anybody's radar?
> 
> I don't know if there's a bug report or if this is on anyone's radar.  The issue
> I've encountered in the past, and what I'm pretty sure is being hit here, is that
> the ORC unwinder doesn't play nice with out-of-line fixup code, presumably because
> there are no tables for the fixup.  I believe kvm_fastop_exception() gets blamed
> because it's the first label that's found when searching back through the tables.

The ORC unwinder actually knows about .fixup, and unwinding through the
.fixup code worked here, as evidenced by the entire stacktrace getting
printed.  Otherwise there would have been a bunch of question marks in
the stack trace.

The problem reported here -- falsely printing kvm_fastop_exception -- is
actually in the arch-independent printing of symbol names, done by
__sprint_symbol().  Most .fixup code fragments are anonymous, in the
sense that they don't have symbols associated with them.  For x86, here
are the only defined symbols in .fixup:

  ffffffff81e02408 T kvm_fastop_exception
  ffffffff81e02728 t .E_read_words
  ffffffff81e0272b t .E_leading_bytes
  ffffffff81e0272d t .E_trailing_bytes
  ffffffff81e02734 t .E_write_words
  ffffffff81e02740 t .E_copy

There's a lot of anonymous .fixup code which happens to be placed in the
gap between "kvm_fastop_exception" and ".E_read_words".  The kernel
symbol printing code will go backwards from the given address and will
print the first symbol it finds.  So any anonymous code in that gap will
falsely be reported as kvm_fastop_exception().

I'm thinking the ideal way to fix this would be getting rid of the
.fixup section altogether, and instead place a function's corresponding
fixup code in a cold part of the original function, with the help of
asm_goto and cold label attributes.

That way, the original faulting function would be printed instead of an
obscure reference to an anonymous .fixup code fragment.  It would have
other benefits as well.  For example, not breaking livepatch...

I'll try to play around with it.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210927234543.6waods7rraxseind%40treble.
