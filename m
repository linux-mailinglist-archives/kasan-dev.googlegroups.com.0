Return-Path: <kasan-dev+bncBCN253FDVEJRBVMHU2NAMGQETOAVUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 415885FF19B
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 17:44:23 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id k2-20020a67ef42000000b003a6f002dec7sf1459370vsr.23
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 08:44:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665762261; cv=pass;
        d=google.com; s=arc-20160816;
        b=dAmyqWL+lsHoQKKEEBK/YxbyngD+ebkMLP3cqxoGapsyh8H/7lVqtNrxRqxBXfR8f2
         hzu2oXGlf5xTuA9WRWXZW/65lQNnZeXl1BJkMzzRLVV7+qKawOQxJiymMBNTZuCfOIaF
         ClOxbIPOw9bBG42Fol1rTz0IDWTpw1VoowQhNUnsAq+RUtPBLIM2n2Um72qgSTSAl9po
         pvPVsbUBH+05mG8xEWMkWYgxOaR4F5mOjQbJDVYw+RQw/v/GJXY1g0M7XDmh6y+6YpSI
         vGuLoq3SOkEqckdMbCCh1bRYV9uXgJcRFpnQaFrlESYx3yUCbd2JzJgDD1PE1CH1gtzC
         aUaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rJJZOAaq6NbB9eCz9XUz7lV4yBiOx2dAiCzr/r/SlU0=;
        b=UFEDe+wsYD2aGMZGCLCEpwZDXmwTwjAo7KiSi3Ws5jXHEuMrQI7848Hs4mdM9Q4JnF
         VoKaCcsj9pH5pwj71f49wellO2x5mft/ZSf+rS+LfGDEYNuGgU0SsIpWLwTvryz0Spu8
         qcDhXFK1FgeBw2wHae/RYg2AMSp4He9q0xjNwyGe8DY4pYV7/HYoGioKV14q1Dtgq4dU
         TPrMX3n+xDFEXf7Zk6J/0DgwPJHTDlRoo9c+0B4raWVTYZuXyzwFNBNaXLixGH8Wjivc
         4JXnNGEeVPGVTjvnvJjOkKuiytTojyZDL5QZCTgKq9hw0KuoTroyRqQ3mqB9Z/DM0Pb8
         jjoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BojrB6HS;
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rJJZOAaq6NbB9eCz9XUz7lV4yBiOx2dAiCzr/r/SlU0=;
        b=fiN7kWq7ZIoliFix3hNzXVskncmC4STQTadCoja+ZUUnfAsX4Rgin6OEYJZmHU64n6
         BUExqA2STM6ibQsyLN8DEBkBCEBT1vmX0nb+hprhWgX6E6i/tIdjJ0c/pz9mARt5zB9A
         c+ClKUbAmMWUbObqbgLJjBg4njBguSlotGtPgOMlGDI3h99/09/DyxOnhlC3uPYnVUDR
         VltvXH7+OYBL4hrwIsvYH1bjaf08UmRJsQTVHl2XsIfeatyJxQ6fbl6PBCIzooNY1X7c
         INKXC6yTlM+bD0bRzVanbJuBTKKexJtXn4jE4VSP5hDTT7Crwu4BHwrRfPoI/17nkkCJ
         fdmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rJJZOAaq6NbB9eCz9XUz7lV4yBiOx2dAiCzr/r/SlU0=;
        b=4KxYyAzkYtQDzRqSnM/EZvv1ng4kVH6tqDJygcEn+vb1rOjLm5Oh6Cr2tkktLj+OzT
         QGkE04fBAGc7kVZAE5biC94X4+qWv6frQckzZybsuJfghlZ13nNkE1mhMeDZz+fmB3Cr
         bT8aUrgHgkxgnO+GVOAlGyfYa/LiTDn1xgJRBSaT9jZsXyGx0jDSsvbjNGlF35MrVLoM
         p4fXCK3Xm/gSbZqu/ATKBB0aZp66C9iXZfWD7pZGxAxm6C0ZQJDhjhB8a+STjNqdUrGD
         yXfIVFMtRA7Iyd8oKkjY62TBvhzEgTjwoZ/79yPARkeTHeam3vHH2qMtq8xRtm2vh0Ha
         T0Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0rhwK/jvR8XOgDsYiyYgQQ05Rng5FSkCQ7rBKWFZ8mfWEQIIPy
	jVmpoYWs+X6Tf4ckMfDc+Y4=
X-Google-Smtp-Source: AMsMyM7wVkXf2oWsp70gpav8C7Jp2bXVEmswjPba50AdaNw35GGlxqXhf6p7Oq8pSU39sqBbCzyF6w==
X-Received: by 2002:a05:6102:a88:b0:3a6:842b:4c67 with SMTP id n8-20020a0561020a8800b003a6842b4c67mr3379179vsg.63.1665762261674;
        Fri, 14 Oct 2022 08:44:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d601:0:b0:3a2:c7ad:e747 with SMTP id n1-20020a67d601000000b003a2c7ade747ls1202042vsj.4.-pod-prod-gmail;
 Fri, 14 Oct 2022 08:44:21 -0700 (PDT)
X-Received: by 2002:a67:c78f:0:b0:3a4:25de:4712 with SMTP id t15-20020a67c78f000000b003a425de4712mr3036857vsk.58.1665762261102;
        Fri, 14 Oct 2022 08:44:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665762261; cv=none;
        d=google.com; s=arc-20160816;
        b=dzPrHexsotLjrmYNNESJEHVDwly/3RLK5wtrw3dL9oNF07hchPTHePGra94+1Zf3bL
         g4VEyvlx8XgGiW3OD74bzcaWJhFHtG/1qja5gcCjP3sKyiwtJgu5qQeIXHDp0OG8o4bU
         wNq/Lnx61Zb5ZJ8Y3gTQHBWs69BIkCZTSQ6f8qeHF67Sf5tsrcctM1+gJNicT14l52Dz
         v0YRRPkmqBQ6wujS9DEOFeHXoO2HK7q/kh+IvSHKiXzX3RcM6sDWI7QYDWJ/OKCl9xIh
         1t7Il7M8zoH7DM0nIype52nud4gEO2S9i+jriFTkeHOXyYxYXTVxzCdkeeThEpTYyb+r
         BAWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=At7eVmlyzkDZqcTvPX5Kyt4U2pb4kxBTHPOzo5aV09w=;
        b=PKNOquotqyZlk87UK+BqcNvC2CznORsezbSdXK1Qqo9HL/tEvbOygzjXp6RWcFhixy
         W4L09hQ/2+SjmnS7m2yKB85O1EMIGBKcQoiyxuQRHixAZL33LZKE9t3Ts7IGA5afw15p
         eiQVa9iNfSjmoY6YQ14Lwf2u5sOvKjaK4ZUVHaaDta0+lvga7nPjLmVcWyPyvBHz1t8T
         wmf2K6Is3UV7A8zdVKDNITd4LULMWiMyV0Rzx0i+AZqUQ2MR9SwxT7ahF9bT7lRPewYM
         0WElbHUlr5po63j5LxjsPQ/cjhAUp2Ff8ESAJrZmJ13Ai4xJrEY2v29BaCq4YXfuFior
         c5PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BojrB6HS;
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id p186-20020a1f29c3000000b003abc1728452si164217vkp.5.2022.10.14.08.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Oct 2022 08:44:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 53335CE268A;
	Fri, 14 Oct 2022 15:44:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91F66C433D6;
	Fri, 14 Oct 2022 15:44:16 +0000 (UTC)
Date: Fri, 14 Oct 2022 08:44:16 -0700
From: "Darrick J. Wong" <djwong@kernel.org>
To: Hrutvik Kanabar <hrkanabar@gmail.com>
Cc: Hrutvik Kanabar <hrutvik@google.com>, Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org, Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org, Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>, linux-f2fs-devel@lists.sourceforge.net,
	linux-xfs@vger.kernel.org, Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: Re: [PATCH RFC 5/7] fs/xfs: support `DISABLE_FS_CSUM_VERIFICATION`
 config option
Message-ID: <Y0mD0LcNvu+QTlQ9@magnolia>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
 <20221014084837.1787196-6-hrkanabar@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221014084837.1787196-6-hrkanabar@gmail.com>
X-Original-Sender: djwong@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BojrB6HS;       spf=pass
 (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=djwong@kernel.org;       dmarc=pass (p=NONE
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

On Fri, Oct 14, 2022 at 08:48:35AM +0000, Hrutvik Kanabar wrote:
> From: Hrutvik Kanabar <hrutvik@google.com>
> 
> When `DISABLE_FS_CSUM_VERIFICATION` is enabled, return truthy value for
> `xfs_verify_cksum`, which is the key function implementing checksum
> verification for XFS.
> 
> Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>

NAK, we're not going to break XFS for the sake of automated fuzz tools.

You'll have to adapt your fuzzing tools to rewrite the block header
checksums, like the existing xfs fuzz testing framework does.  See
the xfs_db 'fuzz -d' command and the relevant fstests.

--D

> ---
>  fs/xfs/libxfs/xfs_cksum.h | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
> 
> diff --git a/fs/xfs/libxfs/xfs_cksum.h b/fs/xfs/libxfs/xfs_cksum.h
> index 999a290cfd72..ba55b1afa382 100644
> --- a/fs/xfs/libxfs/xfs_cksum.h
> +++ b/fs/xfs/libxfs/xfs_cksum.h
> @@ -76,7 +76,10 @@ xfs_verify_cksum(char *buffer, size_t length, unsigned long cksum_offset)
>  {
>  	uint32_t crc = xfs_start_cksum_safe(buffer, length, cksum_offset);
>  
> -	return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
> +	if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
> +		return 1;
> +	else
> +		return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
>  }
>  
>  #endif /* _XFS_CKSUM_H */
> -- 
> 2.38.0.413.g74048e4d9e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0mD0LcNvu%2BQTlQ9%40magnolia.
