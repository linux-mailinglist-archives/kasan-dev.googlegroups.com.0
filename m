Return-Path: <kasan-dev+bncBCLI747UVAFRBDXWUCNAMGQEBXGM4II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 24FD95FDE20
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 18:21:35 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id z13-20020a2e7e0d000000b0026fa9710fb3sf1051100ljc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 09:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665678094; cv=pass;
        d=google.com; s=arc-20160816;
        b=vSav82QSciIVGNE1VKKceaL3RuSrw6cZ6rPTPNotHLd4farpXdWdUTNWXTn0Sv7hVA
         NUV+W5tumGAyirEVaFRRHnTXAGgiOgcKlxQCfS6B4D+6no4ISVXKq7MsKeWkjbDbekmW
         +mQiTsHHT7mF0Q9l2uVk762ovY21QeiTqYVbQFS0ecb0SJFDlDh7bPX32eLD408R7o9Q
         8Hy9gzM3KQeqatSpx1y77aBo7S8yK6uVaW1KIO/6QJ2KTTrRapj4zAp2RhdMtcuMDzZn
         KbWbFPGyvXwCkIxtBj1wq5jMJT0ugJtgSOhWqGue/t94dDbXyfWiTZom5S/k9Mpk+aZX
         fMsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xgbFgg08WQIxmAlVccjIIt/u1CmLTm7UMw6wPjJG0xg=;
        b=0SswkyKH75o5RpQzZ8YJUE7d1IxnUgqYpAjn6nrZ0Y9jNzAiH3AJCf9kkSZDnpImY9
         GDwLHqX3ng9K+OnaoXKcBiTXbkbF3d3pWdTXyEdosQpePsLO+ZEvEfDHaZ4jBo1vbQkw
         wN9+niR0ZI+pZ6VmMoT5hjdrkgSi/BObhkljnkOrclotGjYBV36I53Ls89eSzEa6PZKE
         S7cVXk12kfLSLra7O25HW/EdJc6Js+mv7Cyj0ZfHY39LfUksPB4gaWycIJ51D5MMCLaT
         rNQbKKFBrKyYd7PebjQeCqxd9vg/EJcwJvoG+myIJyY7Vfk28QwwSACSxL6FKUVmlFwq
         MX+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GP4P33Go;
       spf=pass (google.com: domain of srs0=njaz=2o=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=NJAZ=2O=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xgbFgg08WQIxmAlVccjIIt/u1CmLTm7UMw6wPjJG0xg=;
        b=EwcybP6tW07vDmXL1iRaU0972LaNvBMNCiH79A7PJGOJ+lkza+0K9XkHNvZKfHk2y5
         fkIsOlYIIiwcsWRVHzbbiaNQ9H9Ltjyt0xdxXmJ1OuxzOCMexKDyfmWHL3/zZeWOqOOl
         OptBLnzyx22fBzhhQQlMVJF7yd7Rhhqcv5+uWmIaaufQn5quScvzz9B68N34qP4YYRVW
         QHI4AUDseuszAgWSBkeoifpf6DlNzWeAohaG6LxGtG981B4LF9s2NzAgvrhM6iS/zHPj
         16DjN+r5o7fEn2iBid6vRPYGOLgVFZVfT6FmSm8TAH9yHYSonGcP0ElQEkyr2BGh6qng
         Anfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xgbFgg08WQIxmAlVccjIIt/u1CmLTm7UMw6wPjJG0xg=;
        b=x/EKba1V439omJIOYB9Un4KN+5RhB8fO8AyiMXlj4Y/M1x9+pHZaocgJNcut8AHnSq
         mK76hwv8IgJKOzpO6EqK9ETT8K5SxygA8X4UzMgNPhdAJolgPb/e6Z2ja5542n5wl/CD
         hwVnKFbjrwTicRcq1yA96pBfVQmHgZOfINTWxbiDZ9Y7fVrf2tr7Bb+IcyNLq5X5eajg
         RbzPb7B/Gzb8oUyQsEcJiiZafIwTacA+w1vHgC9aYVmGKdEwCKdbjjrAxiJgCytReinR
         D1Eyd0OcCPpCQ0vhFV9EXiBgKqabNNOIHcbxelb1lWfTzQ7NuY89scQvBXAtPYqjB2tl
         0RoA==
X-Gm-Message-State: ACrzQf2FsJlLnJz3kJWsq4vI+vQJ4dLjykNL3fDzcQFWvS0vYWbcGMZe
	CWIKU0O5b5szLU99uS9Ksd0=
X-Google-Smtp-Source: AMsMyM5N1gJGecDSLG3h83YQoA4cAR0Xq8tO6WE4CllVFgvmENNDEXcYO8/7z2t/EHcVltm50pGGUw==
X-Received: by 2002:a2e:9f05:0:b0:26f:b4b8:b72a with SMTP id u5-20020a2e9f05000000b0026fb4b8b72amr220336ljk.389.1665678094351;
        Thu, 13 Oct 2022 09:21:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:202e:b0:49a:b814:856d with SMTP id
 s14-20020a056512202e00b0049ab814856dls939661lfs.1.-pod-prod-gmail; Thu, 13
 Oct 2022 09:21:33 -0700 (PDT)
X-Received: by 2002:ac2:4f02:0:b0:496:d15:ea89 with SMTP id k2-20020ac24f02000000b004960d15ea89mr140033lfr.69.1665678093196;
        Thu, 13 Oct 2022 09:21:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665678093; cv=none;
        d=google.com; s=arc-20160816;
        b=w3Ck3Dpkscz4V3Aup77jnturmV9DsM0oP6epGv4qgPqyMS/nSTkZlCBoTrQBRvD361
         /UkeyRO5NxbGgmKnxdqOauziCRRhfQ0CvTsMdIOllqNDTd644GsCef2LPACsgNB3aHeE
         a43YcZlx3f3C0W+dmmAkmCcL5M86Qq1JL1mkGk+36fKNjgDNldU4miOTBmHTNmQeIQ3E
         OufiESqF2X5hc4tPms2emTrPh7JHo2y6z10x1Xd3iQBXOz8QiXJ5LMJknN7RH7tkq1Of
         mXSQu/bn2wDI+WADYTBudAG73IK3RDJUDATXr8ljLKC5Uf6V2Jq8BZDDmG/ubuC32Eao
         nyoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kPntWr7A6bA616PExnbnx5reDbccdV4V+F7u1oTVbdw=;
        b=eBKP2+KtuxPqNLebinH/7yesW2d7ZIFh9QakpVw8rPL8wulM0ZH6z1i19pFkSNMDT1
         2VNq2mL2+6uEZY7p9LD1PNYjNjEp4AWVj4m1VwGhSSoKlhn/vCDm4p0V5X1LGeH815nX
         hz1u7eJ876cMG5ogGYSMs5b62uOeGDkaQNJinp5RaBA7hpMFmp0J0qn9wrGN4ztxKefk
         z//Ljlye2BXwlK4VgYMCZlzes05MirubkmyLnWpnp+wtvKDl3Ut7mRa3CfgtoEaH4RCK
         0ZvgRX3XbxPGUaaWzC/RktaCJQAmJeAXZadog4LJHHUNOSCLNbgY1qJ/OBDrT4dExqKW
         jOIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GP4P33Go;
       spf=pass (google.com: domain of srs0=njaz=2o=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=NJAZ=2O=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p16-20020a2ea4d0000000b0026e8c45cf59si429908ljm.8.2022.10.13.09.21.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Oct 2022 09:21:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=njaz=2o=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A34AAB81F3E;
	Thu, 13 Oct 2022 16:21:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5671C433D6;
	Thu, 13 Oct 2022 16:21:28 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5f752f1b (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 13 Oct 2022 16:21:25 +0000 (UTC)
Date: Thu, 13 Oct 2022 10:21:18 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rolf Eike Beer <eike-kernel@sf-tec.de>
Cc: Florian Westphal <fw@strlen.de>, linux-kernel@vger.kernel.org,
	patches@lists.linux.dev, Andrew Morton <akpm@linux-foundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Thomas Graf <tgraf@suug.ch>, kasan-dev@googlegroups.com,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v6 5/7] treewide: use get_random_u32() when possible
Message-ID: <Y0g6/sIJMq/JRe6y@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <3026360.ZldQQBzMgz@eto.sf-tec.de>
 <20221013101635.GB11818@breakpoint.cc>
 <11986571.xaOnivgMc4@eto.sf-tec.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <11986571.xaOnivgMc4@eto.sf-tec.de>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=GP4P33Go;       spf=pass
 (google.com: domain of srs0=njaz=2o=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=NJAZ=2O=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Thu, Oct 13, 2022 at 01:40:40PM +0200, Rolf Eike Beer wrote:
> Am Donnerstag, 13. Oktober 2022, 12:16:35 CEST schrieb Florian Westphal:
> > Rolf Eike Beer <eike-kernel@sf-tec.de> wrote:
> > > Florian, can you comment and maybe fix it?
> > 
> > Can't comment, do not remember -- this was 5 years ago.
> > 
> > > Or you wanted to move the variable before the loop and keep the random
> > > state between the loops and only reseed when all '1' bits have been
> > > consumed.
> > Probably.  No clue, best to NOT change it to not block Jasons series and
> > then just simplify this and remove all the useless shifts.
> 
> Sure. Jason, just in case you are going to do a v7 this could move to u8 then.

Indeed I think this is one to send individually to netdev@ once the tree
opens there for 6.2.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0g6/sIJMq/JRe6y%40zx2c4.com.
