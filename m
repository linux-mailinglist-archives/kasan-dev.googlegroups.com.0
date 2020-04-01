Return-Path: <kasan-dev+bncBAABB4PKSL2AKGQEGXSUW6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 20E4B19AEE0
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 17:38:27 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id x1sf18238294pln.12
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 08:38:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585755505; cv=pass;
        d=google.com; s=arc-20160816;
        b=ngbZo+znHSL8PGr8PoxXwsE9VNqCobR+zPJPjnjQcOjP45BMUuTylyE6jok6fRq7UY
         +ZFOBl3/vBmORGHblhVgATBW33bGmyc5cSpmj5kfk3zw9eQJKnxDdFxfktRTrXw0gHQ0
         /mVgq6d6d4xZdAOEc/7y4dyYCLPIm4JTF/hQ0bhF0GLkovviwpjz8vZKPo4zgzMBuJWF
         cU3cJaxx2EtWcAXdH/daZ7njhsKP/mmKX1AlxtyoccyFDyljIPoKKM/c6oGz+Yg4lqrX
         DyTD8Yz+0EiYq0IGWcUShdQce++i3C067J3UNwtdJOBRS+amiCqYuR9F1P2KO4KA5hwj
         7Irg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=taLiWOevsJPyUFkIMNMber3b/PbQ74MPXpMn9Ob/YjY=;
        b=V4ICoQVHExiYXryisDpLNXuKIBlsZPOdSrfDfxstriciXEt5rJfkfgweEV5yFZmOXw
         blW8//bSd+yWKoy38HAaJ6wuy3I9PwltveGiFGOuR1AoB6FiRbMUotBxFks/J47sa98S
         x6R3/bNL0WyOj4mgpjWvazvmuVhwGlnr5747gjRqi4o+cuYd83Qd973fUcweUl0lDw+V
         mbceo/pcPexZj8YsdCwJfIs6zvFlttpU8PPZ5sz7IBqqu8rQpXSzc8EAe/qDeJfhLUZT
         1IbyC26qzehiDeB/FG0PpBHJb1+hc1h9GEklCPzUmKNZv3knH2f/owK2ca6zdyBNIArl
         yC9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=etY4MTJc;
       spf=pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=taLiWOevsJPyUFkIMNMber3b/PbQ74MPXpMn9Ob/YjY=;
        b=HaHaB6Q5EoSQbPfxqSFsCt9+jEzN2tsVAnI1XGjjbazpw7548vtd5SayDkHJ/hIhoK
         iOqO/m9TRQgMCdbDQNBVJQO8ujqz6E6kHRJAf9DusjaT+vj8s8ifecqzMMr4bj+uKrIx
         jGyt0UxCtW1v+aZK60hnIcqLzUiSVXUhtQT2pwm1nkxWIwZkNbQIb79bh4HHGtsJ95ye
         5CvcQRvgT+7mkYOVbAwFT+JUMB2K1ZymN/Oekp7l5bcS7Qh37snAZTjkV8GTASA26V5z
         +/ffruBPiB5+ZywVGrGWiwSnGVjfwStnNASJeeDD4CIhEZ2ad5jUglET9nKnwmh3c03x
         bE2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=taLiWOevsJPyUFkIMNMber3b/PbQ74MPXpMn9Ob/YjY=;
        b=ZHrnDJqr6v/MTt4FQwdDdK2Mw2th0/DasGe4BHMMnRfRLHUofSksAbTbGFLA4kogtA
         SNJuVxFmkTY8yBL3P3dbpHKkQ+mUr2MRlMyvDSOx1iIZXeNEvs8gyxv2Pbn/XyNitK/v
         YFXBtR+7Nr0zV7kG+i43N4mEPm1nJ76ZxrCQXhOVeUh7kcG6TL6JClxuBbQ/iqXbOIwH
         F0D4LXSlMHYAFMV+jh2B6/Uwmmx8Jh1Bt+osag1wqxvhFm5tP+HTWsq+bomnA1+5361S
         G2CC0+M5+6zynPhf6A354YMhzPDT+eMdax1My5Gj6ovIjWpx3cZnR042VKcCOJLlMWsH
         f8Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1Tl11gCnhYqg6nG1nZA5aHR2XdHPbGIZqJM11ytbLEcRw/x+Fh
	lgUpU4cphSoUOTwAYj4VGD0=
X-Google-Smtp-Source: ADFU+vvLIyD2YKoPt5FNpNRfDjPVAxwJ04YfiEKBoYlImC9SMXWbY1BytnyCop5xQHbcqRVe1FXiGg==
X-Received: by 2002:a65:6801:: with SMTP id l1mr23716540pgt.105.1585755505559;
        Wed, 01 Apr 2020 08:38:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:a35b:: with SMTP id v27ls70697pgn.6.gmail; Wed, 01 Apr
 2020 08:38:25 -0700 (PDT)
X-Received: by 2002:a62:cf84:: with SMTP id b126mr23480673pfg.316.1585755505175;
        Wed, 01 Apr 2020 08:38:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585755505; cv=none;
        d=google.com; s=arc-20160816;
        b=REPX/n/e9ZIAU56AZ/kreznz6g89UvL72VCKzuF2GCl2g8FQQIlXHxs068rfU5kT7/
         Dn8KDcGMdths2vwnfsB2QpYiZBhtXrja8Q2RQbSMp/1c0swRU2Y2paGjVcKz4kYD3uov
         3diCRxYdAK4g0jbiZ8qyB4ZTVYn7DPds8PVYzDGn/Cl0pKAN+Ytsn1jg6M59P5WDmhvA
         W8otX8DoN/wCh88JPsO9an2LledEy9GSXHJMuAYOT9VHrPqeYkvm1lKhny26Thb2scSs
         Bj/XJvzKAP1zF3wq5OUCneRHEeBxXbdAzDuNdw1KyLe+D3NiWENgmtMcsblx908utZ74
         Gv4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=qomlG0sBzdUHT0CZagbkcG4SS3PvcoD6hon087POT6A=;
        b=ts2ykaDML/PVPIIqiclHnO6z9AltgpIQZAIoarcX2HjCtZrj6oHNF4e6wMF1rRBS0M
         dwjMQbzzBYSE6DBpngOesTKShlQ0ROL8JmS0d7s9KLhZ2C4xXMD83q6BXMvpJ+Iu9EW3
         5DvJBntjdkl2065cBK5Cch9j3kcUK045rTPn+uVPK2TKPl2bGIxfO+hfZIfZs5uIwz+z
         VNDpnMSBTSYAF5urNc46Eyylxrva9nFzx6chHvPiTllQssPRIjCJE4W+NU/quGmh3AOy
         d6etv5q3OFhvXWcB3njy8oh/UwLeH99E4Rqe2eos729YcACegraCP4dfvyNbse4lqSjr
         9eMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=etY4MTJc;
       spf=pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x12si74054plv.3.2020.04.01.08.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 08:38:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D47AA20CC7;
	Wed,  1 Apr 2020 15:38:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A550835227CD; Wed,  1 Apr 2020 08:38:24 -0700 (PDT)
Date: Wed, 1 Apr 2020 08:38:24 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Joe Perches <joe@perches.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	apw@canonical.com, Will Deacon <will@kernel.org>
Subject: Re: [PATCH] checkpatch: Warn about data_race() without comment
Message-ID: <20200401153824.GX19865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200401101714.44781-1-elver@google.com>
 <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=etY4MTJc;       spf=pass
 (google.com: domain of srs0=getk=5r=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GeTk=5R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Apr 01, 2020 at 08:17:52AM -0700, Joe Perches wrote:
> On Wed, 2020-04-01 at 12:17 +0200, Marco Elver wrote:
> > Warn about applications of data_race() without a comment, to encourage
> > documenting the reasoning behind why it was deemed safe.
> []
> > diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
> []
> > @@ -5833,6 +5833,14 @@ sub process {
> >  			}
> >  		}
> >  
> > +# check for data_race without a comment.
> > +		if ($line =~ /\bdata_race\s*\(/) {
> > +			if (!ctx_has_comment($first_line, $linenr)) {
> > +				WARN("DATA_RACE",
> > +				     "data_race without comment\n" . $herecurr);
> > +			}
> > +		}
> > +
> >  # check for smp_read_barrier_depends and read_barrier_depends
> >  		if (!$file && $line =~ /\b(smp_|)read_barrier_depends\s*\(/) {
> >  			WARN("READ_BARRIER_DEPENDS",
> 
> Sensible enough but it looks like ctx_has_comment should
> be updated to allow c99 comments too, but that should be
> a separate change from this patch.
> 
> Otherwise, this style emits a message:
> 
> WARNING: data_race without comment
> #135: FILE: kernel/rcu/tasks.h:135:
> +	int i = data_race(rtp->gp_state); // Let KCSAN detect update races
> 

Yes, please!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401153824.GX19865%40paulmck-ThinkPad-P72.
