Return-Path: <kasan-dev+bncBCVJB37EUYFBBE42733AKGQESKXZ6HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 34E9E1F3C34
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 15:22:29 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id f16sf25285417ybp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 06:22:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591708948; cv=pass;
        d=google.com; s=arc-20160816;
        b=0qsuhviE+0DMEtgyAFfkeu2LYjrQVe4A12xgBt8mmGEd+rvPVEEfcTUJRdw/Z+uppv
         cQR6j3nG0cjWhGuwFd3nefCpX8kV9dvAedTth0Jx7+HYtA+PPrv09moYx25tqHBN/VDA
         jsDyPCaBNMC62u8/Z5SMw1A31z8eQyv6gVG8VEovl20TMX8iyT2v1XVj+shU+z9GwRHw
         WQ/bcH34+4iMCJ066/lblBjehodgByLbOXq9NJilwsBiYIVasVTW6whGouh96zKCWlxe
         W1/uJuGn7q9tMkV91dYad50YDrybnAFCpC/VTHtL/WSi72G+KFj+yGuwlELPEW4CASpi
         K9vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8tLXrGl/Yxin/Yx4fTkzZIc8uO4eNKMFqfxhG8DkSCw=;
        b=yvJ/nJRvdicQZradxoE3mmNInrvF1ou857RcLi1Y+XAF+ZxSOWtSNP4cA64XNS7cIO
         xpN/7QuKQD12G5jrTXK1lHdeLWbX2Hoj32O3Ja+w/TtmWwU1tzefJ9abQ7KTc7MpjQmE
         r0jtvO08ovPkqBAYcwwzNzVVNsGy5GwK/oMksdMCTSOXuOGy1NKg/MrNca3mZamzgcfa
         YHstVcJmFWpKxy7TyUSh7NVwXwTw2gGcWWhkGS08LUL7OUQiBIKwCIEXNbHOIWtxnFos
         JKzQ53SbSppcuHN/ngd43DSoqI+Kp/sgC/tM/plFvq0o9ODIgpSe1n+Zwd7SzVrAKLq+
         zZLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="e/4lachl";
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8tLXrGl/Yxin/Yx4fTkzZIc8uO4eNKMFqfxhG8DkSCw=;
        b=KFEg0M8r4mM7MicHdRoIKQw4LtuXnqWXfCa80ElFxWrrGZe6GxNxUA4X6LVJaSe2Qv
         oso6EjMGBYH1OsNKclnEU3QAQA/xEPhHbJh4GHwKoIBO8RBDSjVVLHh0BoDScKPqbCNF
         4bq0vMxQ1fw2gEP7WLb2BOIGO86afsdDYP6aTdJoOeJ6gJR59ecNF6A2aCiiFOJ6HLkQ
         vHY//tIxVFERmjw8GEL3QC5wZbNNussCGDLsswd1d/WEESNU9mKUlgxbvkqrDysktaMs
         v4Nwt8KNiBexElQyT+vfRNrfLuTNej3saU3As/bCms7F2FJYu9t+nramyfeEnZkQeqJI
         p/Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8tLXrGl/Yxin/Yx4fTkzZIc8uO4eNKMFqfxhG8DkSCw=;
        b=sTN74W7mALZZi+CrpzFZWc6ljZZtVgnI8835EPeg1o2AdfOYk2O1vmZDy5Vpi0+YpL
         rcRnFI0FdX99fUMjfz9LYeBiGuLylV0t1Od6sSnrhBetiX5nX0iKQRe6+T9bLU8gqye7
         Mj5bY4RUaarP1/wQpLCVUnGqlnO1EnV3r243RskrQ34sMu7vRfBAEklQ51J0Ci769TQS
         kRMTRIxHeuVkgXeq6PKvUToVQw/xedO9bMZADW8HOOcgZY15o7iO5KG4aMJt6WFHwKkf
         8Ap3/t8J8vuZYyGyKb9inNgsahHlgh1toFGddEUimO/g6U5/+M1tsw1PiyJIuWPI+1gl
         gqdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327iv5pZs3+E8aIQEnQuSnRaSJKFmVkzWvlnkL65pQM338NtGif
	I0pm+V6sCIs+1ypIKN3lP70=
X-Google-Smtp-Source: ABdhPJzIpqgO4f1dQ7g0BbbhcPNvmufTkLoaQnHpJjRnrsSvNSVG/O5vYS6ombKvNPLJjbcykYkn+A==
X-Received: by 2002:a05:6902:4e9:: with SMTP id w9mr5897256ybs.311.1591708948035;
        Tue, 09 Jun 2020 06:22:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4d42:: with SMTP id a63ls3672829ybb.10.gmail; Tue, 09
 Jun 2020 06:22:27 -0700 (PDT)
X-Received: by 2002:a25:848f:: with SMTP id v15mr6738142ybk.473.1591708947716;
        Tue, 09 Jun 2020 06:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591708947; cv=none;
        d=google.com; s=arc-20160816;
        b=vWZLIrvtyyqxqSEdbjFMJoqsnFA9BAXBEyDEP57nKMRI/faHXEz8ef+Ew0oJvfSyYn
         cOtKUePBRcGnlBiHLsMJOk1Njgk4KMOvjKqqt+Ypwn+HB6g68+E7PjfxsgWv0wwYIo0I
         d+6IZFcsAdouojB9f52WkAp46Tosln53fjSSpGVIBxTLT6uPy0v/JFXXQohcvJHBC537
         CPDXAHDVfOgxVSokkBO3swt2JDqkSFA/6GqiLYW54j2S70n9U8F41M0LRBu4zq76izwO
         15+eDgxAvr4666c3SXP+iiBrQ+7JGbMLnzXEwKtj1/8S/R1sU3Q5Fm6w3aEjqiDslHUh
         QKWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=QT1A2ya5Fpzfn2G4ZykZMkvIfOkU+Gyhoa6P8Pc2fU0=;
        b=uNNhwAixOlo/SfIDplOmmb+f2cFrzFvZfVm/KIXg8fWXG+PPaz+nhs3AiFhCnh10g/
         NFjCJdYugQ1kgru7Xv/FleVH937ZJchCWl20cAXJebWOP4O3eYVJftpmfRdsQisYeUz/
         KI92hmkEW7mRl3TH1I39rnOtdG4nhBmEzYpaaTxtMJdXCuIL+sY0pdelvXiQ7xwgac5/
         1JZx4l/4ydmab7/CWt9MwQ6lydO8Y7d8H8phiSitU9mZSvkYVvdsQpT38/fDsHv9P+06
         dwlQ5rQT/+b0MHtepUj85c7KqvN81lxtwFXr0Grgrk6BV5RiosApxBMDoeRaFWhMjKU9
         Dp0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="e/4lachl";
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id n63si105131ybb.1.2020.06.09.06.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 06:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-427-Ggj7XPHUMBaBXS9XPUVHtg-1; Tue, 09 Jun 2020 09:22:22 -0400
X-MC-Unique: Ggj7XPHUMBaBXS9XPUVHtg-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 1E426800053;
	Tue,  9 Jun 2020 13:22:21 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 7A1E97BFE2;
	Tue,  9 Jun 2020 13:22:20 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 059DMHbm019124;
	Tue, 9 Jun 2020 15:22:17 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 059DMGEf019123;
	Tue, 9 Jun 2020 15:22:16 +0200
Date: Tue, 9 Jun 2020 15:22:16 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: gcc-patches@gcc.gnu.org, mliska@suse.cz, kasan-dev@googlegroups.com,
        dvyukov@google.com, bp@alien8.de
Subject: Re: [PATCH v3] tsan: Add optional support for distinguishing
 volatiles
Message-ID: <20200609132216.GE8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200609131539.180522-1-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20200609131539.180522-1-elver@google.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="e/4lachl";
       spf=pass (google.com: domain of jakub@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Tue, Jun 09, 2020 at 03:15:39PM +0200, Marco Elver wrote:
> gcc/
> 	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> 	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> 	builtin for volatile instrumentation of reads/writes.
> 	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> 	* tsan.c (get_memory_access_decl): Argument if access is
> 	volatile. If param tsan-distinguish-volatile is non-zero, and
> 	access if volatile, return volatile instrumentation decl.
> 	(instrument_expr): Check if access is volatile.
> 
> gcc/testsuite/
> 	* c-c++-common/tsan/volatile.c: New test.
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>

Ok, thanks.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609132216.GE8462%40tucnak.
