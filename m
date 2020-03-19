Return-Path: <kasan-dev+bncBAABBRXHZ3ZQKGQE5E2I2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 405A318BEE5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 19:02:48 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id l5sf2184201pjr.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 11:02:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584640967; cv=pass;
        d=google.com; s=arc-20160816;
        b=C5rDlVB8jTbTGx0tsmAdpjGNrKINFzIBz0iNobjwQ5IHGU8PUwyxI8T6+nQrWPRwYB
         KFBW12M4MvVNJfKw5KzgUbx8G4Hq6Aune6t95o/Fa8MQEImdNrGVY/91UVJAFF0kMDQM
         ho+GhadcZ25PTUTOwu1mHBA1pFph+9ALq1of67p8c8IM/UG4j+WKYI0rk9/viH5ACSsc
         ipEIDMnU1VcW6RE4w3qeaSpmYr6ximAzWn+kYM7gZUFSzJsV2a05XMnmHLHOGlXw9FT/
         niNkMsyQ2xGWolphJTAGanND2KOD+SKURX98cSWt5500+9LIlCJa0sh9827VleZUJXo9
         6KyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=5Tj95I6TZ87edUYpve1hnkc3jVFAfS/ZbDZ1phtZccA=;
        b=TkOxRAG6+PTkbzWRuzOSDkOT97Oj2pO9WDyOdjhYKYZUAg/OpOZIJAP1P/oAF46YWB
         NjYKZxMIJGY/SmYki5I48mWa027YPV34N/7/t7Dbx8Sb6w7Ew1ymo7HUT8kSG5AYjSA5
         scBp7IywYNQjTV9UcgLPrFC0CEfwEhNDyfkZOjCAJKrsjhZ93ro8H6by8QYejYSlZcre
         v9DKgvEksYd5Ef1BvLbsWPx2D4kwNBfzaz7lxfvIAF7bHp/RLVI3Hf1UN6B9n+dgdCmi
         Y0I8SqVRETR3yMZMsBXWBzCDJxa9SIpHVQ6yuHF37Kg3A0MqD2xDRlCYbwW58DaOcfRg
         hKrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vWx+iONK;
       spf=pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Tj95I6TZ87edUYpve1hnkc3jVFAfS/ZbDZ1phtZccA=;
        b=f4MYlnKjNWbBw2Kp3yYlvjPbbzRSGnfxX2AKHDc4yeTNpEsKivZI6IjWKkG59pNqyd
         2pYbwjaMj7O/UngG/aX7KUzUXMMRJu3QNwAZyMUrYK5gF6zallG0Dc294AN94s70qjUm
         NHYW4KcwzDuyS34pwLg0+znznILktPsH0flFJk3m/IzqorQNdw69pIqpW7PDkWKbzZ2+
         VDYeZWw8mMHGDPmav7THvGXCNiVXHkt9twy278g1ZxgDU9j7/wsgpyUaSWrTzjqTivxU
         oT1sCUFVh7+CmMftmZqDL7kkBVG8kbMqdise1/IlsWaaycMZXztJs+k2SJ6ZTcKcIKng
         1jIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Tj95I6TZ87edUYpve1hnkc3jVFAfS/ZbDZ1phtZccA=;
        b=K7CjJTgbTCJmJp0mvO0bj0GMzkiWQlC9WBc+7qoxy+r145yt5w3PDCyDEfdCvA7Npn
         UH6FFsOCDrm95hFxyVQvzk1MEHdh6rYo2nj5xXmTuy7r/kBeUiqzLoET9elbZSfvp0NF
         Z7ypM92uyaaTTVKCPNEzITqYSDAb4XCDihBVbEJkeuvLyGbbt3JeX8fcSsG4aRtPFYno
         s9P+qdqkeyd3/XluKMbbZWy9PR8uEYqLRm1XRqXTHhIBEJPODNGPEQWPQ54farSopOBU
         aWrV0aqyIK0BxGzwzwny/zIAiXx1Um/MRJD7p9Z2dywBIV6wBa+omb39RuQkgKPNkXXG
         fJJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0MarWgecfCMmYQon0fy3dEF7uozoeDSykkTHWST5ZHwfvtB85x
	KZszAQuaWJK64hFj653OPNU=
X-Google-Smtp-Source: ADFU+vv/aTiKI2+ASPk2hfg/0+/vWgQEiwzIVS78IP/KmjycCERGV302gjoK6ELKYo6oIn5enOTGBQ==
X-Received: by 2002:a62:a110:: with SMTP id b16mr5380263pff.263.1584640966861;
        Thu, 19 Mar 2020 11:02:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a701:: with SMTP id w1ls1713047plq.7.gmail; Thu, 19
 Mar 2020 11:02:46 -0700 (PDT)
X-Received: by 2002:a17:902:d712:: with SMTP id w18mr4882540ply.238.1584640966447;
        Thu, 19 Mar 2020 11:02:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584640966; cv=none;
        d=google.com; s=arc-20160816;
        b=HSCijDNThDYYgabOcjaNV2aWgjonNkoT5GVhSsM1FPFOi66h20TjTiZhcOFyBu6fK9
         hnrGD+IAyoA/+mNNXvk0Wuzb/ZEb/DdVgzSo6lVoURDrUDHU13JoTtMal/yF2oZ+D2ng
         MKyH8BrUjjPbrvnftQjAXNO4U1epH5E1YGPYU4A73MpJmVlWmHk2VrbuZHPww4AxTsDZ
         AchhantO0EsqEp+inyRhqXo9Uo5316tO826vfiWv8HA9C0XAacE7dgy2XGs7klJ4x05k
         cJQX/ze9uf0+55Us4fb8dbuFHpDih4utrj/Ireh25WoVLR82iVFjWiSEfnWTCyES4F4Z
         kjFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=gLAAkNiHKZp7dRfCl06Yc21YGZE1DDjB88kIBEqvt5g=;
        b=sfQA8lNUWK3FNOj7PF8OvhTm+GJcmGkYBNmieK56NamQrUA1IkZvrZ6oQDFB6G6y1u
         sDKgGqQgzfic67g5+X4DWRdBLZcSgtc2cXjntc70t8XUhjSnG9VSDU+9DNzrlSAhBonD
         QlfDwvCJfkeA3hozD0zCetCyVpSRDvBVrb/iG5gR6SIlHEq1fBY9WcCnA/L/U8yWoRza
         wAJ6cczpFbTr+/8mVTUTsMr7tFr/NN9gxIbJS58EXHVM6U1SkksNFVRwVq2QIgh5+Lzx
         fkb+4hyE1lbn3E+UwDaNF+vzJox24ovMrmqc965IsFJshw9DAce+TaYF9Bkxz8gSYlly
         7k6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vWx+iONK;
       spf=pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s20si246763plq.5.2020.03.19.11.02.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Mar 2020 11:02:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2A3E72070A;
	Thu, 19 Mar 2020 18:02:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id B4F7535226B9; Thu, 19 Mar 2020 11:02:45 -0700 (PDT)
Date: Thu, 19 Mar 2020 11:02:45 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Introduce report access_info and other_info
Message-ID: <20200319180245.GA17119@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200318173845.220793-1-elver@google.com>
 <20200319152736.GF3199@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200319152736.GF3199@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=vWx+iONK;       spf=pass
 (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Mar 19, 2020 at 08:27:36AM -0700, Paul E. McKenney wrote:
> On Wed, Mar 18, 2020 at 06:38:44PM +0100, Marco Elver wrote:
> > Improve readability by introducing access_info and other_info structs,
> > and in preparation of the following commit in this series replaces the
> > single instance of other_info with an array of size 1.
> > 
> > No functional change intended.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Queued both for review and testing, and I am trying it out on one of
> the scenarios that proved problematic earlier on.  Thank you!!!

And all passed, so looking good!  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319180245.GA17119%40paulmck-ThinkPad-P72.
