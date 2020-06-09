Return-Path: <kasan-dev+bncBCVJB37EUYFBB4GR7X3AKGQEPZQZFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 142401F3871
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 12:48:18 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id p8sf12785752ios.19
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 03:48:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591699696; cv=pass;
        d=google.com; s=arc-20160816;
        b=VPXAVuLnC0FZgiHNBG5fgw/eK+d1aszhZK6dP9Si/xd+YDNF4vRVSmm/hX6h5h/wzp
         LqAsB4UGB04U3KrBfMcSwEkDg0r9RAf68qL2Nm2HnOqPcg/29+1kpr1fdbgBeZlC8kzD
         /p1hfuH5Wsg1gxl0g4PAJg7OGdfMfLLzocmIPiTR1o7dMvN87YZtfm7wtWzdtWHKDalP
         uiBkj1YVHsWeTePyLGhucRi5x7WnfsjVrtbmAh+vDvJp7nhziMDiLjg/GF99KJx7l8gX
         AOj3MFk6PWgoBOGSJtvZsdrHZbqKHnXXHoLIwzgRfSiHDvnsVCI0Lbxm7K38ZIir3OGm
         HoBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CAB7575wCuXWG3Q9CKXSTFb/CmGKYDpmCDqj9u581Yo=;
        b=XfrukJ4h1mF47ypPJRcDYJur0asBU2pWW48auykgU+NBS/X76lzXqzhZjJJsYjj49N
         l8eq76LqMBiz5U8dKL2JEc+74gxBnVbXqBj/wazCHyOTtZhXQjZlxXjwcNV2BE9Hj33M
         FmygHjpgmfLFJ/9bD5t7I3PmSi/0vwLhcYfyiFfgOpuIINjO3fruvFgImmOgZ+MnB+wc
         gauFnncZIu236Cur0VjG+ig71RJe/Fggz37C82sfxlSm2TLX56v/+3YYe5OXVNybZUDb
         uPS6flyTu++dlniLli6bvv0hZaf6zjfuyVaC4Dmnhx8awl5odHITtRcFAsywE09dd6Cu
         Txmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IvMJaryA;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CAB7575wCuXWG3Q9CKXSTFb/CmGKYDpmCDqj9u581Yo=;
        b=r1ySK3TtdAazEd4ck4pIXYv9gT2/sdctiqE4xbba0gfhl9W/f+wpocx0a5Ttqv2Iz8
         ONC2UMqPyJbiDv5WDrEtpLDgbsLBTYYBH6v59TphklTiJSfz5RYkT4RCa/yVPSKSTkgR
         LIUFnCU9qCKUPKXmwZOlqNaOe4lFJkCOww9PDpAox2/k9NuNJv8MEqRU/9ohSDzr8E1q
         tWQknOqpyIhlW/mTCFtTwkaXcOR7VutZxLoH7d3iAGM4QazO8FDWOPv1ArB9h4WIrVsJ
         DD4tJIL1QTXxUQq75pvbU6j2Emkr41PmRy69odsHUffqDwj/PDnTszMDdyw8X41UzlXz
         HVpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CAB7575wCuXWG3Q9CKXSTFb/CmGKYDpmCDqj9u581Yo=;
        b=j3UIG3aRrYo2d3J7YhPLj+dsqFeEiTPvCijJRPvDn2khKUir/x/59NoVoVwBElfHJn
         R599cLgr98PZCily9og94ZYUPCpAaPJU5ORKK83nrJSvRteoz0j1XQrusI91ADoWwn6+
         +ExXMT9IOW1AUl7K+/qGYqKMdEK8p8044LJ+IkWwk68CgWMqtjUSCSrsWYluu5+BqeG7
         IeR4Xn7g+abKGQlZNXK14rBGkuriuJ8cAXGReshvVPwNkP59srMTh1oBL/L2spYIbjPM
         7xrExDBO6Rui/FJ7LskzxxuPMia+3L1GIJiNK2sPaGyZQml+yFVGJSJJG6OxG490Avfx
         96IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iXmADKT60KOBve9F+VpaCCnZGSWYdYVtE0gWBs8p44pBRJq7x
	SXSBvwggNXoZr8pbPqdepqI=
X-Google-Smtp-Source: ABdhPJyj4Ka255gK3kAXUBhObcs9c/5dcrlOxFE4gMlMrUVq9UR5g+xWo0MB03Whtb9DvwL0MpndkA==
X-Received: by 2002:a02:958e:: with SMTP id b14mr26785153jai.126.1591699696624;
        Tue, 09 Jun 2020 03:48:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:351:: with SMTP id x17ls1081962jap.11.gmail; Tue,
 09 Jun 2020 03:48:16 -0700 (PDT)
X-Received: by 2002:a02:b704:: with SMTP id g4mr23121340jam.138.1591699696307;
        Tue, 09 Jun 2020 03:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591699696; cv=none;
        d=google.com; s=arc-20160816;
        b=E+908vR/LFrkGldxhYxBrUFMhBMX+2fyvRWsFRhUgcFRfLcvnJCgQjAMqMgzPJcBnA
         AUmVOwsj+TQqXm4bMmWPNKf26bUhHXq/F4e3rcQs3VOtWbkVZYLgH3nvU5pPeF21Y2Wv
         H3xTkGAJlzfoz9enh73Wr4sWax5Pj1LTPbI4tm93aJALFqPFJyBK/WPUbxwHzf8pwlRk
         gvw5fXhi48xYnPiqSFEnaHZTkDtr6I8GQWiMwtuZgHDVsVxCjQ0T0JRp5+xwRDJ/kDvY
         APXOy8BuBTvd9KAikzR19wUZoUSFAp4564JhUNL3+tUZxuiQ1P8MgNhpoEIYMlwi8wuF
         qKuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=MmxkwvLo7ID37/lnbZbrR4KfzYMMrXLgGwZwqxf2kfc=;
        b=ZBYku8uMScV30OLunwiWUa4XzvGq5kroTYKSKmSoqxak4r18W7zi3dupJgmuNj9blu
         V1+o8xCWeLEQUHPt/OzHWpW0QTj50N6JCswnSg+rbp23kWOhmXULD3NTZuzoIjnkvfUO
         ncZiR1wRzubZgQOEq7IJaNuRA+MX7v9cq23pbvyzOw3WIcKgDKpEySRmlWmbd2MlkwbP
         ZmDsOHMBSiPj+GsdaRwKjALJV/koCwAr8+aP1xoVuv6mYcLiOlJPg9rkt4u8oGhAESXj
         a1hxdrHgWXmhao7cMxEDoAU6epaL/t2tCXUSDGXnYI3eSLdSNUjJk2cmoB8wXKm0lODd
         V0pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IvMJaryA;
       spf=pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id i20si70930iow.2.2020.06.09.03.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 03:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-154-Wa5FaJ7DOBCoecxft_L-nw-1; Tue, 09 Jun 2020 06:48:08 -0400
X-MC-Unique: Wa5FaJ7DOBCoecxft_L-nw-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 3EB88835B40;
	Tue,  9 Jun 2020 10:48:07 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id CB38889262;
	Tue,  9 Jun 2020 10:48:06 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 059Am3Zw008365;
	Tue, 9 Jun 2020 12:48:03 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 059Am2LB008364;
	Tue, 9 Jun 2020 12:48:02 +0200
Date: Tue, 9 Jun 2020 12:48:02 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>,
        Martin =?utf-8?B?TGnFoWth?= <mliska@suse.cz>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Dmitry Vyukov <dvyukov@google.com>, Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing
 volatiles
Message-ID: <20200609104802.GA8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200609074834.215975-1-elver@google.com>
 <20200609095031.GY8462@tucnak>
 <CANpmjNMgyHEZYqa4nEhwT1wJ7RY6WyxPqJxJgHBqRuZkS=LcKw@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNMgyHEZYqa4nEhwT1wJ7RY6WyxPqJxJgHBqRuZkS=LcKw@mail.gmail.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IvMJaryA;
       spf=pass (google.com: domain of jakub@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Tue, Jun 09, 2020 at 12:01:24PM +0200, Marco Elver wrote:
> > Do we need/want Optimization here?  Optimization means the option is
> > per-function, but to me whether you want to distinguish volatiles or not
> > seems to be a global decision for the whole project.
> 
> Adding Optimization here was Martin's suggestion. I'm fine either way
> and just wanted to err on the conservative side.

We've discussed it with Martin and the end result is that it shouldn't be
Optimization, because we don't want to support mixing it.
Essentially, it is an ABI decision of the tsan implementation, which can be
only one in the whole process, because if somebody tries to mix
code that distinguishes them and other that doesn't, one still needs
to use an implementation that does distinguish them and will assume that
code that was built without --param=tsan-distinguish-volatile=1
is never using volatiles, even when it means we don't know as the
information is lost.

Note, for LTO that will mean the param needs to be specified on the link
line too.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609104802.GA8462%40tucnak.
