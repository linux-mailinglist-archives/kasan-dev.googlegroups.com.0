Return-Path: <kasan-dev+bncBCIJL6NQQ4CRB6UIWWNAMGQEFNOJ2GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 27ECF600E7D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 14:03:08 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id s5-20020adf9785000000b0022e1af0e7e8sf3659358wrb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 05:03:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666008187; cv=pass;
        d=google.com; s=arc-20160816;
        b=rfo+7GLqvriDvipZMlC9xntcpPhtHh0QaUZL5KYCMddrPh5v1/rJl8n4DE+/kR+jJo
         IaaJCqq2ldUSkzqGxYD6Z8rBVfKuazTi5F60FEl3mPZzHIRoX7MiB5FZBMcvckpAkG56
         +ej7RxLBY+Xq6E0iBNhqZPjxeB+I00eqElkHI/Dov9EujIu+sStmxf3yyrL8rKTMoJ2Y
         ZtIRGjk8zPyRp9/3Ag1/+g+ZSTGX0H41Tg++NI/GgWBaU2nspmCqvqxrRvlA0QhObg4n
         sCfQaP/FrYvCWgh9w5o92Bkc+Xqp2pX93cPaa24pK48Cf8EhBFGZ4n1RT47yX/TZJuI1
         o8+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=7B0xVQgUojHdPjnN4ERnV320KwMJmfdCLpVHvcZp280=;
        b=CTEo/qC6Z3aDpU3IPoyCcTJgpaZ+dmmn3YORjwtRyvjKS5a21IXWtMRT1/vOnhlYKi
         jazcGZ1j7ILTCdM9/6PzmAZk3yqYeIPsV3U19AjIdxoXpJN0faVXpkV1wo9l3ticMMgC
         XdtTH6w1rt7pmf59NDNOlsD2neLQWJDN4UoTcf72vbVGdcYO0/oIHmx9onQES/VJSTsS
         G57SdjHdeHVB5fcEqYso9DhRpdLHpJ6qLDAiIXyK23fLomC2Jf1ynAlu4ETUpr4z0R6h
         OKbZgOh195GqtbLeTNpYzI7y5r3/1IXoq5GGrQ+CE3fNjJH7rWYxtGSQMadPaYC4WF+x
         TGyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EinRM8cm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=+HpnUQkg;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7B0xVQgUojHdPjnN4ERnV320KwMJmfdCLpVHvcZp280=;
        b=Zr8qP9WtNzfPehjqTl9hNU6pgDl5iO4yKgm2qB+kZnZ7EmFgSz3lItxhKjkA8ywFsn
         fv77WnFbIBstr5Tr8IbLvoAlrR2IJIHQRmrOc1rP/EAvqLCzp9FgNJS0aHLAl/7TmRUc
         qq3/XRuvwHnvp4/cU5gE3/413T6wVIjJ0JvcUN3kdb0FUQQpVl5CbjBN8N6EAomNWpsD
         MUCm2FpK1s7eM31+1kDnV1LQ7ks+jpLYHZmaQetWr+yInHlt7r5FuK2UFQ9+3EJw1r3q
         kWCipgTYzUdCYNU/ucuh958vnit3Qs3ge7QD0HMC5I38wIC+8dheu0inWRgLG7L+NbIQ
         9Nkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7B0xVQgUojHdPjnN4ERnV320KwMJmfdCLpVHvcZp280=;
        b=GHT5EevEm8dwFVbG9323XeuBoIIAHpN3e5wOsxkTC0MMiXnqLhZsu15jQM+7rkPBwx
         Ef8pv3XGiEBMHNPNoJ0m83p6POlSjrFzFOLfs7M9obfiNLwMvDGNtdRD5admTIc1EQh+
         m5tDOpl5cbIQBOHqDQIUFjvKA5hInnmM9Ke0/AqHsG145SzLjPqDsJhz7vwcpZKvuP8G
         UfdU6VIFuVhbrCRI2IUyf0P7aRNBGRxYWHt++soiVS6zfHW/sa6F5Pb4H5IfDzz7IJu+
         CuCGNWcOqDYOylMzzCXpghpE6sF4hDPwXj9eZp646bjECU+azc6YfmOE/xFoGzr1MD1v
         73NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3PkfMRdpbnVczcLlKjfl2ZYdPFQey05dPmdIpWebIOrfMA1ggY
	FAlEXMgYREk3LHkl7O8oOsE=
X-Google-Smtp-Source: AMsMyM7DHCNEU1kBCYggqIWyRQVg/6ND36M1bSWSIHiVQ1uRrj6/b692VVB5PVrZWosi27DT/4Bo+w==
X-Received: by 2002:adf:edca:0:b0:231:2e6c:760c with SMTP id v10-20020adfedca000000b002312e6c760cmr5822587wro.600.1666008186594;
        Mon, 17 Oct 2022 05:03:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:231:b0:22c:d34e:768c with SMTP id
 l17-20020a056000023100b0022cd34e768cls1183659wrz.0.-pod-prod-gmail; Mon, 17
 Oct 2022 05:03:05 -0700 (PDT)
X-Received: by 2002:adf:aad1:0:b0:22e:3667:d307 with SMTP id i17-20020adfaad1000000b0022e3667d307mr6269420wrc.359.1666008185502;
        Mon, 17 Oct 2022 05:03:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666008185; cv=none;
        d=google.com; s=arc-20160816;
        b=XMOsNrd4EHABSUJ6ZJ95JQMbjyPvEshrxPRpnG2C4RVRkDT2+/FU40s6BR1w4dt1Gm
         UhegZcO78j5m7MnAuqVaV5PUdDQF/ovOrzOCtpm//v3eueT7Z355eTnoNhTvp2qw6hAs
         vnxcVWjdRp9+TN+hiqMkhZoAxlpRevEEyR1STQHNis8D8ValEG6QVWQoAkawB4XVR+Vq
         /9JBWnBFET4nIl5skUR/3qq0QaAViKEWem8mdsk1YWpF0leOMXIlQFPGxQTASStBjDAd
         85Au0uRBi1psBeU8a4jNNQxmk4ZFLzdgY6SHCGjrLNbEHShFfu3qC11Nr4XfyzXeSeVr
         rBAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=H9rmmj8x9/pRGSP0rhWzAN2XdXyBU8aire6+hcOWaqg=;
        b=bTRUhtUo5OPk53iDw9VZ1lNLuhbmfo3Ra+4RpRwCuGuGIrI57tXodl+HHvOTn/zPc/
         +bgqGIjBFrJwODoF/HI5QXfb6nSIevoj/ju6ynaCuvMAq6Hoq46rbMPf3aKVtM2s249p
         R4NskJh+n5ygwQzYB/kw+o5gezD21sijuEDczcyd0JeGyDUbuKocewuqTKrPXdMuNO2G
         Kc3hwUy6OvHXTIM6tA8F7dFQSVn+aY3PQp5CYWEfkJFDyFDRwMZATi0RZmMw7xwKEWEU
         QNgVrBypNlwLkWRz+arKSrccMfRO3LqjG0RlPqaReN9H1WCI9vzwxYV/fliffvP71R2o
         Dy2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EinRM8cm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=+HpnUQkg;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id ay3-20020a5d6f03000000b0022e04ae3a44si423733wrb.6.2022.10.17.05.03.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Oct 2022 05:03:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dsterba@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 22E24205DF;
	Mon, 17 Oct 2022 12:03:05 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 9608D13398;
	Mon, 17 Oct 2022 12:03:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ovthI3hETWM0JQAAMHmgww
	(envelope-from <dsterba@suse.cz>); Mon, 17 Oct 2022 12:03:04 +0000
Date: Mon, 17 Oct 2022 14:02:55 +0200
From: David Sterba <dsterba@suse.cz>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: dsterba@suse.cz, Hrutvik Kanabar <hrkanabar@gmail.com>,
	Hrutvik Kanabar <hrutvik@google.com>,
	Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org, Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org, Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>, linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>, linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: Re: [PATCH RFC 0/7] fs: Debug config option to disable filesystem
 checksum verification for fuzzing
Message-ID: <20221017120255.GM13389@twin.jikos.cz>
Reply-To: dsterba@suse.cz
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
 <20221014091503.GA13389@twin.jikos.cz>
 <CACT4Y+as3SA6C_QFLSeb5JYY30O1oGAh-FVMLCS2NrNahycSoQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+as3SA6C_QFLSeb5JYY30O1oGAh-FVMLCS2NrNahycSoQ@mail.gmail.com>
User-Agent: Mutt/1.5.23.1-rc1 (2014-03-12)
X-Original-Sender: dsterba@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EinRM8cm;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=+HpnUQkg;
       spf=pass (google.com: domain of dsterba@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=dsterba@suse.cz
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

On Mon, Oct 17, 2022 at 10:31:03AM +0200, Dmitry Vyukov wrote:
> On Fri, 14 Oct 2022 at 11:15, David Sterba <dsterba@suse.cz> wrote:
> > On Fri, Oct 14, 2022 at 08:48:30AM +0000, Hrutvik Kanabar wrote:
> > > From: Hrutvik Kanabar <hrutvik@google.com>
> > I think the build-time option inflexible, but I see the point when
> > you're testing several filesystems that it's one place to set up the
> > environment. Alternatively I suggest to add sysfs knob available in
> > debuging builds to enable/disable checksum verification per filesystem.
> 
> What usage scenarios do you have in mind for runtime changing of this option?
> I see this option intended only for very narrow use cases which
> require a specially built kernel in a number of other ways (lots of
> which are not tunable at runtime, e.g. debugging configs).

For my own development and testing usecase I'd like to build the kernel
from the same config all the time, then start a VM and run random tests
that do not skip the checksum verification. Then as the last also run
fuzzing with checksums skipped. The debugging (lockdep, various sanity
checks, ...) config options are enabled. We both have a narrow usecase,
what I'm suggesting is a common way to enable them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221017120255.GM13389%40twin.jikos.cz.
