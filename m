Return-Path: <kasan-dev+bncBD5LDHXSYUMRBDED7SMQMGQEHR5EAZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E5F055F6BA3
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 18:25:48 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id ay21-20020a05600c1e1500b003b45fd14b53sf1947150wmb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 09:25:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665073548; cv=pass;
        d=google.com; s=arc-20160816;
        b=VOddk85Ghl13d3TuUlL2xvfTFobmxEmEcSlgz3h3/dWCzWpbV5nIqaGjU7pOPlt8c8
         a/MrXmIR3iag8lqAb1JMH42eSUQtKxkT+bAGS8Rr5sFtNbJ/FEGlHZs9h/cAAzDGzkoU
         7lUU+pTR1uLrRvecH5i+3tq9vRlmNM1wylJWoywAz3hx+WBDJeLQZafxKBh2oEmPCBmM
         Wcs7YhlTdTMYusJi5DlJ/RpzleBzTCyHWKk8td5e+Sx+edso2H6nCdl3QdueNUYLNo2S
         Buc+Rwyx+vpDhEGaMMe4xGQHjpKCVrYy/1fh7lOOgmakc7zwJYYIWlLkS9R13CZN/KyO
         GS7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IdHVp7s6F0k8frAOX8913B05uV1lMWmC4poMa5k8OmM=;
        b=wnDO5ol4VsdM1Mf0eFbQ1W9OF0pqd1+zBIvezsn2B8w9a0zj7l1OZdH6ZYFQzfKNIX
         FBBRa7sVJ3rQarYWyVmQ+5WwzyEIqBoyFfS5PKJTE7v9t8K9VAYn2MJ5PdW0Kmy/wxDx
         Vxh0LVWdLrieffEgZPh4IwmMmv+ta9Eyf1eich7oWk/sNjeta9HWks957qn4P42P1hbE
         Q9NdUnEHgFsA5jHJh5ebDfgm0dZbn+PFCX8tlrNGQsrfNh7mFauNwZmt6EmXwuLm7c+y
         gVkTzX2ewwHZPHKLKLVNIPsrm7aLJA67REyU4aNFx+kLb0lvPqBz/r3Npi1OgzjVN6NY
         Za5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BuCJHwpP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IdHVp7s6F0k8frAOX8913B05uV1lMWmC4poMa5k8OmM=;
        b=iQRKyzm1x4B9SlMzvalmf2+4VBj+w9ILrntVpoNnZ5kA8Div65wKEdqXeiVZC+93e6
         dsOfJfnWZODAbbKudGcGd3DJbTKfzmIniWmyWI4CNKR1Cs1MIDVO14vWypfjr9BZVyeV
         vmwidUMWMgbyFZ/qeDV3cNWBUB5IRlCfKdTBRcfqYvascCNGdKpsFZ4dTGEppNyGvDrk
         2XOdLYpb4quv0WQyrY+rrc3fk376tSVVaVDeR0fAjeR/AL62E//W2/GB36r7o7muQ/oh
         mqgg1MeXB0InhH55qMMuSJMZj/z1qLwc8xj5bJp0HSzTj6uu4np8t0R6i/cOhKSZDiQj
         vM+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IdHVp7s6F0k8frAOX8913B05uV1lMWmC4poMa5k8OmM=;
        b=BJ2Yp9oBMwRharqQe/Q1Mjf0rGYq+SZeoy5sLH1rUT55WvHwAH87zwVOSi3GeIkhIt
         ttm9IkqqUDzYPRSM7X3d9Yq5bcomalA8XUA9f/9rKs5qOiYBL9038G5y8GUEFHYFb8K3
         WS7216tH6sMQ401Fq012wj3ZXg/wE0vGgHkUuYw3H0rudYKqpQ/tsIAE+K4gLWw2Paqh
         /T2l3vQz+2Ji3QwXZ9dc+8CNd32KzlZLcUIIv9RE0jVkub+YLRwEmi1jsMRuruIXHAHj
         3IAwFzx0g1Y8AW2aGeQ7vJnz4tgp7Z5zVaYrrPq6H2nYS5XzQW+2dW7/yrX7teth2nmV
         bgNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2cp4OK2ju77EtJf6PdMOYtnqrqHhkX4jYnxGOg8U+5JHnvlpmE
	QNjR3GuC7jN5zaKs9c+Ssl0=
X-Google-Smtp-Source: AMsMyM48ELRHTiDEhZjKKlYgx/7hC97P/Vbiqm7Rif4gsFNL0Kb/V4Z1uY/3q/viZ+PAZCsx68UNCw==
X-Received: by 2002:adf:ed41:0:b0:225:3fde:46ea with SMTP id u1-20020adfed41000000b002253fde46eamr514621wro.345.1665073548393;
        Thu, 06 Oct 2022 09:25:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70b:b0:22e:5d8a:c92d with SMTP id
 bs11-20020a056000070b00b0022e5d8ac92dls4392732wrb.1.-pod-prod-gmail; Thu, 06
 Oct 2022 09:25:47 -0700 (PDT)
X-Received: by 2002:adf:f591:0:b0:22e:504e:fe76 with SMTP id f17-20020adff591000000b0022e504efe76mr517162wro.553.1665073547445;
        Thu, 06 Oct 2022 09:25:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665073547; cv=none;
        d=google.com; s=arc-20160816;
        b=hV0mY/BI39kRdKxG7w0DT2ceyCPf3rYT435ytFStdDwW6y9p4hP6tMhFq9zmv/78yH
         MQyDZ0yV5bex6/LqPilBpBEgpk/pnAt6oeve1grZBmDXb5JKBC7H/11N0ivnF0WwmFH/
         Y2UVlFVSv/jDxn/KcWNJ+3LacfLEvu2JLqfygiF8g18nC3JelXnIuql51CB0nOEgyhHx
         ylgh5blYUYmzuUaOtZVSB9l+PTrwg+X2slGCFSMXFmbkGwgKbm7utL9hRqGRXbieuxsj
         9tzrpOIrmoJsW/GlvaM2O51w5mi4YX1jNIBRPV67gGWKh07HvS7lWykFCBjDs23u92OX
         82og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=XCQ01W/Zak7b1/Z15iSFiNNO+LnDKjRUCwgq9owN358=;
        b=U9Fuc/jx6VoOnx3otx35n8//JC5JZLHy5m0QEBHibx1kP5hf5S9nY3fIS35kzp/yOu
         TxzoD97GTEPmSW+WWQDeXpQHFLZCsPdoMCfX6bu4azJWDm7d9eTi86G6yCQkPG5JGRND
         I/7ObdGj6GjzkjvRy44VQ25fy+vcolc6gPvJfdjnf/s/JtbxyUGv3UD8hzfUGUXWd3Od
         czUerg3S5fcn1JPiUgblS8ZBi+JjYOCaupA17VCqiNcXPontYN2yM/RTXORahnZJXO6P
         QlFSWG0gTfncgXqSV4d8a47QaQ51HMpzoE0gOHQVTN1zBHgc4fKmzYGVt9feHo/uCJ+h
         Tftg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BuCJHwpP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id d8-20020adffd88000000b0022acdf547b9si599665wrr.5.2022.10.06.09.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 09:25:47 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2FBBB218E0;
	Thu,  6 Oct 2022 16:25:47 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E0B0413AC8;
	Thu,  6 Oct 2022 16:25:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UOdXNooBP2OJIwAAMHmgww
	(envelope-from <jack@suse.cz>); Thu, 06 Oct 2022 16:25:46 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 30DD3A06E9; Thu,  6 Oct 2022 18:25:46 +0200 (CEST)
Date: Thu, 6 Oct 2022 18:25:46 +0200
From: Jan Kara <jack@suse.cz>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-block@vger.kernel.org, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-rdma@vger.kernel.org,
	linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org,
	netdev@vger.kernel.org
Subject: Re: [PATCH v2 3/5] treewide: use get_random_u32() when possible
Message-ID: <20221006162546.hgkrftnsk5p3sug7@quack3>
References: <20221006132510.23374-1-Jason@zx2c4.com>
 <20221006132510.23374-4-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221006132510.23374-4-Jason@zx2c4.com>
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=BuCJHwpP;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=jack@suse.cz
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

On Thu 06-10-22 07:25:08, Jason A. Donenfeld wrote:
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Looks good. Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

for the ext4 bits.

								Honza
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221006162546.hgkrftnsk5p3sug7%40quack3.
