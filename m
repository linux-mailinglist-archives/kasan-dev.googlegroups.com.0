Return-Path: <kasan-dev+bncBC4LN7MPQ4HRBXFFVD3QKGQEIYHJIOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DF4291FCDD3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 14:55:56 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id b65sf1019352wmb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 05:55:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592398556; cv=pass;
        d=google.com; s=arc-20160816;
        b=dbrNRRMFNYYdqqj+ggr9gnbBI9/DvatPc7LSFUU3oidmR2+jA1dYQdb+MFaNTyGRER
         51RNNBrx+I958J8B/fblwjnFht8+tP+93g6XTIhSgCUfd2EOQkNlpOM8+D0NXupe2Qqk
         FN/GnKRLcMW6tiKFG004wHthXEK4sqkWuyoifIsjGFVo0qCOnwDlKaGfkE/TKoskc5aa
         7ONkYFJbA3LnCnMIqfmU4TrZgx3WZhpNqOye9qwMT++S3pCv6AbOvi1a0A4aSM6KmeA+
         DR9pIoUk+wsRXXPrWBZFkkK0fQeTResCKgxs+KCPg2KWH+ARMrBVyBhZCDaeNhJNIwEV
         09xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0NDuYoinN9PojMx9vEMf1AAUHz2bzsfHn6c4AcMgHSU=;
        b=lXy3YCcReK85DQCoujWYWrau2i0Dj2xLnwstYqywsS9msDCdJ+pHX40EjD3hJUGBSf
         Y60EqYnTKBNRJQRvqK7Ctl/3jJFrnskvymwCmsmnEx+sxIydkgn773is7ud0Z5xtbZoX
         0Ve5t+EsXoHCWozxkotOa5ctiCKfcuzipYJDNDBJbXnO7rwI4wkstnlzaRtjPCvUviOE
         XGtvqaChw2+ZKT3D4iXYEtj0N/UNQE4wL8kSbuETsjgAdkGblEp8d+5FuHM/Gka5Cd03
         6ZNFZTB9lOSvIZOrXFmT2dDEjw2ZbGOSVvIZu/5ngHF2/bdNSccu1xAZ85cDJS13YdWb
         0bvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0NDuYoinN9PojMx9vEMf1AAUHz2bzsfHn6c4AcMgHSU=;
        b=tFCPkywbvxsh3FwSImNjSSf7VXUwgvgm2Ev7gq6xlxSb049GBexLnA90KSgmFW49Pp
         hCn0PcRslpcCOxQuijWRSCTPSoIolYqbrz1JSx4CTFEDrdeAnmbMiuOAeFYuy26sbg16
         Tz1LF6LGyFUFu+UQrAut7ot6/lCAwgBk6lZJ6PqW7j6D3APwIa6HeJYkeryXrCSgQINL
         2Y2kg1w3Gw0v61tAVQYeG9dlsuvl4cCOqqWsggD3nKuj6mApNCrd5TwvdaUQ1bVKeWaz
         AfamlCC0kYDhrf7Suqn7W7BJrJJMmMVCs2nR/C0Tmeahc+jWHzghQFh0JZohD0QY+yhu
         JQnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0NDuYoinN9PojMx9vEMf1AAUHz2bzsfHn6c4AcMgHSU=;
        b=tA3BctqsNz6PxPH8WdpDx1Z2Eg0qRE+LwliBNENwlNZBQg1DGmj1sHaDbOEY9UMJq+
         i9JLRjaXjQ89sHs6Kc0T20Ag7/+R2s1upqwdP2OOGbln4R1iRgh5vM3b9fJNI09yGgiq
         ewwTz6iuJ01MIYxaXZSeIP8a5mVDKLZIXR21L6aoKKzdjAFTqhZtDurAioGXzH+jWdrO
         oMVDE7CYKnrHzj6BahDNAd8oitJPeQOnt6D6vxLxMKnuVFoWG5GT3F5y42h4hClP1doe
         /B8/rJUMLsg+5p/1EpYi9ZgWHvnN1WbRq0w1SJN/90ekoIirHTEei5b+s1eUcqAOMqKd
         tzvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Xy+NvWOpXsdPSckTzDQOyUH2h4nemlytH/Zn1eVhXmND9XBC4
	zzUprbtwoA7xOdzWaeJy7M4=
X-Google-Smtp-Source: ABdhPJzTI1LwcfUje+G59d0C6gQTJv5G23uwr3sUwaz7+0fpsvU+G+1pmCSwTbJ5A3UgJD70cLVsCQ==
X-Received: by 2002:a05:6000:18c:: with SMTP id p12mr8973099wrx.66.1592398556620;
        Wed, 17 Jun 2020 05:55:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f608:: with SMTP id t8ls3117097wrp.1.gmail; Wed, 17 Jun
 2020 05:55:56 -0700 (PDT)
X-Received: by 2002:a5d:5006:: with SMTP id e6mr8877494wrt.170.1592398555987;
        Wed, 17 Jun 2020 05:55:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592398555; cv=none;
        d=google.com; s=arc-20160816;
        b=Tj2mDh1YpL4ydA7ijL9rQxIdF2DdvF9jnv4f88OhAHDm3dOBQNNb3cBEaxp3r7A4Hv
         oYu3Qrw4a4MfVNzlBhmHrQuTbhNwdzf2rZ/vMo+9AM1vRnRTQHXk7h7B7sMLXE2mg/LU
         bRWwwnNHsadWVNiAGrOYTGevqzyEz0hN6LAg5jN4LV/48FlZ/N2zkffeRNewAh3ogpo+
         +Gt6Qv7XjFR6TJYblnYxkM1kVFSjHDN24I7ufqa8E8TU7OqMqVs3a+FYCex18N2e7ShH
         i3qqbCXnihgehn4l3Wktgzf3nboCDHwUhCpYhbJnXwzwjANPvhV4Gwm7msm2YzgMLywN
         Tj0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=fOVgSeVqTVqWvUfLoOdj4nt+48hh42lucWZp1VWswtg=;
        b=lj15PiNE8x3TovJtX2K534VKRzkJqKh8Fan6+9Qjq80WthX5lOw44rIEQ9KOlJ5yg2
         3lWqtniUZAv3zUIFKu2H27UNURV3PGDhqTArRSXp9gw7PfkcvSLA2uF7S5HrJgm5WkGw
         ClBrt/e5GLY/l9iLr/lItLnQ/zudaLC6AvR1G1unUjbWXohqU7S10QiZ7sKzJcjCtEwe
         jDfraqGz1X6hyLRjSQTxVUdxpXADweFmuyJUkTzRFgGQagvlSerzGJiB/UFuAr8dRHkX
         vCNryQVwbYJCL3HRflfjain2k6pg2cdcDNRLdY+Ib15sme+5mORdBjKLyoKCxtbMHk0p
         LKjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-f65.google.com (mail-ej1-f65.google.com. [209.85.218.65])
        by gmr-mx.google.com with ESMTPS id r204si295961wma.1.2020.06.17.05.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 05:55:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) client-ip=209.85.218.65;
Received: by mail-ej1-f65.google.com with SMTP id w16so2198650ejj.5
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 05:55:55 -0700 (PDT)
X-Received: by 2002:a17:906:aad8:: with SMTP id kt24mr7265073ejb.527.1592398555771;
        Wed, 17 Jun 2020 05:55:55 -0700 (PDT)
Received: from localhost (ip-37-188-158-19.eurotel.cz. [37.188.158.19])
        by smtp.gmail.com with ESMTPSA id mh14sm13501385ejb.116.2020.06.17.05.55.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 05:55:54 -0700 (PDT)
Date: Wed, 17 Jun 2020 14:55:53 +0200
From: Michal Hocko <mhocko@kernel.org>
To: Matthew Wilcox <willy@infradead.org>
Cc: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200617125553.GO9499@dhcp22.suse.cz>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
 <20200617071212.GJ9499@dhcp22.suse.cz>
 <20200617110820.GG8681@bombadil.infradead.org>
 <20200617113157.GM9499@dhcp22.suse.cz>
 <20200617122321.GJ8681@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617122321.GJ8681@bombadil.infradead.org>
X-Original-Sender: mhocko@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as
 permitted sender) smtp.mailfrom=mstsxfx@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed 17-06-20 05:23:21, Matthew Wilcox wrote:
> On Wed, Jun 17, 2020 at 01:31:57PM +0200, Michal Hocko wrote:
> > On Wed 17-06-20 04:08:20, Matthew Wilcox wrote:
> > > If you call vfree() under
> > > a spinlock, you're in trouble.  in_atomic() only knows if we hold a
> > > spinlock for CONFIG_PREEMPT, so it's not safe to check for in_atomic()
> > > in __vfree().  So we need the warning in order that preempt people can
> > > tell those without that there is a bug here.
> > 
> > ... Unless I am missing something in_interrupt depends on preempt_count() as
> > well so neither of the two is reliable without PREEMPT_COUNT configured.
> 
> preempt_count() always tracks whether we're in interrupt context,
> regardless of CONFIG_PREEMPT.  The difference is that CONFIG_PREEMPT
> will track spinlock acquisitions as well.

Right you are! Thanks for the clarification. I find the situation
around preempt_count quite confusing TBH. Looking at existing users
of in_atomic() (e.g. a random one zd_usb_iowrite16v_async which check
in_atomic and then does GFP_KERNEL allocation which would be obviously
broken on !PREEMPT if the function can be called from an atomic
context), I am wondering whether it would make sense to track atomic
context also for !PREEMPT. This check is just terribly error prone.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617125553.GO9499%40dhcp22.suse.cz.
