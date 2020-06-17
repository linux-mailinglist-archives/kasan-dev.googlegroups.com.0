Return-Path: <kasan-dev+bncBCM2HQW3QYHRBPHTU73QKGQECNWNC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C8E51FCBC5
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 13:08:46 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e5sf1246658ill.10
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 04:08:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592392125; cv=pass;
        d=google.com; s=arc-20160816;
        b=zORjVnXCYQDL4p0gasJF7ZcftFbJurpZsDlL28xz3Es3bV6JB/iuUFnyFAiPkCdJKQ
         gUGh9eqsX2qO882gPyNlymuGlASxN7BJlLcEkANxyEmal9hb04JfchSrrbHSSgcG2YzE
         zSKVw7S5THDlLrHQ3+bfuS0x7WRFAsyeeySxI7U3MOYf28eznvoJLHdNsBozBI78JKH+
         hpEiyFKQDvnOFvb1oP5xZIWN3F5UoC/cNe77cOyBDIZZCA4bi96FZozS9XfeYtg2ldvM
         gXQCFenUv+6Kktm8X5Vx2RLoRhpngsqFDeAkhxZ7K9le2Z5Oe84KJdqzsihx4J9PCRpN
         F0TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dlO0yAhbqI6iVPuXtYxhFE9hLGr9fn4tJf0S/FjuFRs=;
        b=WOkYLJPe/XICH0K+W6b6RuBb/R9TGRjXQbsNFqPsXJiwpF4sh0yXO6/iiXIpmAtsDy
         LiwAnfAU1gtbrWXsi6KIzB84TIyWOzbzvzO5zdr1AhhM0GPdFoLFCq+sAn6BxVegxAD9
         KKfLKcVzPYFQmrzfDFV4ObimUTCklllPDxJFuYcLnHWA/jQz5eQ1EDWmqq4GpzZQQSKF
         FLBP9BYzA7vsMmQDe+mgQGWuvufxo3QqtH8vsYbSIecS5pvyZtVVT1aX/ncQJMTW5FlC
         wIxNP29xJoxwRPDR6yfgVFrHcsDsuNNSdUcojG5RidJ/ZIoikyEL3mFSZAiJjpt9KXer
         snEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=uEnXH1vp;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dlO0yAhbqI6iVPuXtYxhFE9hLGr9fn4tJf0S/FjuFRs=;
        b=oI6fNrGBuwx4SE1Y8RwAElzrIyFrWuVaXNGgl93kfOZSYbjlkXTEVxviumwJIz0Fob
         YfQOZXSOTgAmGT4wGnXZ6Yq9a6r+opYg0TwXDUuyAXXYeiMPmuhuQSHnZHGWgLO14Bei
         fnPgk9+nofERkKH10Bo+jhup1GGXTsMffm/4E4fYatYtE38GfAtRqactuyFWrNpFrrCi
         XLwS/upKDQFZhCEbTrPJ0NjtnqAjXXxKmEZ/lIg5LnOLyMg64cnS8+diYqIvCTw1cfwX
         e7VzWPPmubZoE97zYsoe+vV4UlGYyAlzrJvNGZHtGEvPiuDB+Gy8btIxI9eSfTvMsrWe
         Txeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dlO0yAhbqI6iVPuXtYxhFE9hLGr9fn4tJf0S/FjuFRs=;
        b=aknoXmZw4IOBvrIQDlp5jrIigEvQvorIz0akrQHKn7efnV+Ie9+A2vaD+igFBjZrL/
         04mIql6DKW88+b2RDuTyxOb3kduD0DTXHnZvog5qNwPXUxbXPgeJe4IPe+gARK0wH1ws
         FJx8vSN9Hc9cKNtzIh4tIgswaK+OG/7sx2msVxoEpy3PkpalXNTYsF6/NdwGjS6etFYm
         aVpLMyocKtSgQPri2+1aEjOFK/i2bmQqpWP5Gy9RednL9eTSBcfL6yj5EnCq0Rmb0/Cm
         cjL90xqJFC3I2J1ZedNezAMqXSonHBYEOchxb9z2950S3UBU8mEtS9XuHRafjOR8e4JE
         uc1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iwpUvS2n4PJ5uxA9/PSCD7K7yYzpz1hCIBtzodPZA1q6nXyL7
	EUgoV++6pHV1fLFMUJfRju8=
X-Google-Smtp-Source: ABdhPJw2IdyUoyZFov57/kgXVibtG6qPG9R3LIQu2rPeRPgXmFWMESZs8SNUhl2dQpG1NbalDhX+WQ==
X-Received: by 2002:a02:c802:: with SMTP id p2mr31079698jao.111.1592392124876;
        Wed, 17 Jun 2020 04:08:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e93:: with SMTP id t19ls525399ilj.9.gmail; Wed, 17
 Jun 2020 04:08:44 -0700 (PDT)
X-Received: by 2002:a92:a1c9:: with SMTP id b70mr8107551ill.198.1592392124585;
        Wed, 17 Jun 2020 04:08:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592392124; cv=none;
        d=google.com; s=arc-20160816;
        b=tZmHOLekJS7L3n4+3AfqhWNM4Q/yfrv+cEaQxXVI6/6vOa8x70XnQe8VCZ0Cu3EJ5r
         7q5BHWu/PWuzDlwAXx5GgMWqpm7CueWdORGdeEvfsD6a6BOzDCdyGZXteoKKkpeZ3MFl
         cxYSGuDpvJPSLivFGQreIXz3cpNSmsMhFeBxrraowWr8so9N1k9X9kWFD2XHZo2q+5+7
         CLfAogPk5rlMYx+pCDN+Gvd9WF9Jt9B7ZW9+Wad4/hnxhRJHIt6hEgc6OYA7FzxSgHN0
         sJ1VFyYG3ooEWI5EPdaSWsm2RMDDCZnyqlVwJjZUi56dSCuicKY6afZOvcLkfevO4I2B
         3UPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6UMFO2TmbdpnJT0c5EXP2Aydp2MaQ5RYJc+GA8ZrxVg=;
        b=YxegEwMAANG5l9SyY0sc6F/+fqMEftJ97FViubh0isSVUPqy8+6kaTAj0hti/JCi6n
         zb6lRmhfHJNRpy7eAiTV02NreDwoF1UCAebKDB4S8iyrWt7nPjKP3cwd9M1Ox59ASOj3
         LzE4Itj0Px/mHJomYs9YLQgmdU0W64dPe00CzUGZxC7F3AyquFuiyKC284Rmt58ltC1m
         8Ea+gU5s7kl06Tt6eXs2zZtCfHz7Fp6TOm2BUtk0FZbbieWz+d1m3SXQ0CnyFVTs/i4W
         QBx76XsyfZ4wePE6KQeuepqKyAq8AN19SrY9hAcZ4itQ28D8bn6ayTaa1sGngzNiln4y
         S8hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=uEnXH1vp;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id k1si62607ilr.0.2020.06.17.04.08.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 04:08:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlVvY-0007BQ-88; Wed, 17 Jun 2020 11:08:20 +0000
Date: Wed, 17 Jun 2020 04:08:20 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Michal Hocko <mhocko@kernel.org>
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
Message-ID: <20200617110820.GG8681@bombadil.infradead.org>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
 <20200617071212.GJ9499@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617071212.GJ9499@dhcp22.suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=uEnXH1vp;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Wed, Jun 17, 2020 at 09:12:12AM +0200, Michal Hocko wrote:
> On Tue 16-06-20 17:37:11, Matthew Wilcox wrote:
> > Not just performance critical, but correctness critical.  Since kvfree()
> > may allocate from the vmalloc allocator, I really think that kvfree()
> > should assert that it's !in_atomic().  Otherwise we can get into trouble
> > if we end up calling vfree() and have to take the mutex.
> 
> FWIW __vfree already checks for atomic context and put the work into a
> deferred context. So this should be safe. It should be used as a last
> resort, though.

Actually, it only checks for in_interrupt().  If you call vfree() under
a spinlock, you're in trouble.  in_atomic() only knows if we hold a
spinlock for CONFIG_PREEMPT, so it's not safe to check for in_atomic()
in __vfree().  So we need the warning in order that preempt people can
tell those without that there is a bug here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617110820.GG8681%40bombadil.infradead.org.
