Return-Path: <kasan-dev+bncBD5LDHXSYUMRBTMC7SMQMGQEKWRMLXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6251C5F6B8A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 18:24:48 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id u3-20020a056512094300b00497a14e7589sf809063lft.12
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 09:24:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665073488; cv=pass;
        d=google.com; s=arc-20160816;
        b=OlY/PR5w40nFv2+Nc5hQeuRTmvcuJk7/lLP6jigvq0yvt9UpwQNX3vlUMzBHoadb/+
         Ds32rIfNUipM1Zp2WC4UN9rVzjPiWa1VMSoQ3Ji3fRrp6jZ+fq2Y7vtt1iLQxh4mapJx
         wJxViLllyeNKLiVLY4DIZY9Sz9OoP76XsRXRrRrgAkfjPTk4bXRJVZYdGjmHiMigw0sk
         K44eSoGCVOUjoTtfBUdfo7pTHQonbDnN3fdyC6UA9EjrdyjH1gRQpNGRWYZJqYrH/GLe
         RvJF7weS8/j/vDrxFiZpt5xRZaYYZ+agAL82bWsnba0wtCQHPdSsfKdcU/PoR3TbCFSD
         i7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=IN26zewsO+w8jJZsicHQSvDlkNK2XGg8E8MPIln0K/s=;
        b=OYXOBN2x2XtFT6X3QVLCGZIDiHMMwRn3omsva0bhNYiTwTJI4dAsqg73tPSTEFikMA
         3eVB2iFr1MduaxccG2o9xxxXRiZTafa0PBvW8xDRTRpUjbSRcYXp5NkMR1bFjZAAwbXY
         Ou3+gHmSXv5Im4Goyx43KQTwMmL1jgRxLNzySrKNHIBypFHvoOJxvKkGu2jEWYtTU7hv
         t/KkNit4i4XF5Sh3yy43vf+2e9LAUhNKC06184izIWlnW4Q4kdswBeIirY7b10Rne3ut
         8Si4th6lSgXk2BZF0cQm42Eu6xNjaRIiCEooyvPWK+Oulzu4c1OB3Ej85obV4WrBZseF
         alBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UpMGEnz8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IN26zewsO+w8jJZsicHQSvDlkNK2XGg8E8MPIln0K/s=;
        b=ncrsLdI+hGgiudLTY/m2ClpwREt8mN3YIJUwla3ghFvWa4+mjU//KL+jzSEtjnMK4d
         L4ZAYH13PhhUBRzGPdI2kO/S4HbwRJdTUYWRMnXy4SzQvUYvMV4Lzk/TSOShfqxgl/Gz
         cz2CBs9YT7w+4jYyzXEs2+4jdFdtOKkZN9jVCwFgZIwH/rSdSzChIQrus9uut2hBwTjT
         w1+rqS2emFqrmtEiiW7dKqP2hwzdCFUJusWYOeeuOUvFjoiVwrxerDkQPhaObSm+tQ8n
         cbCg8hVLMTLQjPORKLT6h94zDameeY1jXPAW5CwNcMnzdGaFFpmRxyeb71PMYnE+3y7J
         dPCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IN26zewsO+w8jJZsicHQSvDlkNK2XGg8E8MPIln0K/s=;
        b=tdSLgK9BLbH1dvVWJs1evQqb+Wv7bPbJOHKDCNN454+TBsTfkOTBQaN9sX+P/BKgxF
         5HbFSErHOcDCk4qa1ZJVQZn6lq6phV+5yxzr2OmKQAQagyl1StI9Tz1UrkPae4Tk8rFi
         KJv8zJamGRYJ7SXzSyJ7p05G4gKlDZQyqkNSuh1tSJJp06ySE4xQ0Y1/DGhfMOksW6Qh
         neM/07vsH83lUIjzzTepJy4+6TnXRLNkaoDwJeKqgsM8RToe3JHWAMlNNiHY5Vt0Ddv/
         kzeCwR8qy8zoiulAyrU+YQPZsMOYVupIgkokBIAu22KCfr2fRFtBr3oweg5PVcJxSLJr
         YkYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2AShxs0/BU1ZRZsvY/H6L3Jt5CrVnt3TIstK7zOQuHDRvclHHt
	gwEvGcJqtKDk96KmHRTYGNA=
X-Google-Smtp-Source: AMsMyM46H/TiJ3gHwjHI8b+r4XGrqum3WAV3XcfpobUHfdS9DIHqAA/4Z5V6lTCIEMF36zJ0TLbfsw==
X-Received: by 2002:ac2:5cda:0:b0:4a2:2436:112a with SMTP id f26-20020ac25cda000000b004a22436112amr307972lfq.295.1665073486274;
        Thu, 06 Oct 2022 09:24:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:23a4:b0:26d:df68:5d5c with SMTP id
 bk36-20020a05651c23a400b0026ddf685d5cls510279ljb.2.-pod-prod-gmail; Thu, 06
 Oct 2022 09:24:45 -0700 (PDT)
X-Received: by 2002:a2e:b046:0:b0:26e:2a8:df8 with SMTP id d6-20020a2eb046000000b0026e02a80df8mr169858ljl.241.1665073485061;
        Thu, 06 Oct 2022 09:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665073485; cv=none;
        d=google.com; s=arc-20160816;
        b=SMlkye+9bfcAvXRsHjsjPs+hY196txoVRMRwAdjaytbdngT/WLaWMMBUzTTMYH5+cO
         gw/IfbZe8utFOKiWu7j/BOQGOYOYxQXAcezwiX3w5GFvlrkZcGkM8sOmzMMbrz7Pv3Hl
         eF1sGLnhW/YKrGX0qKfOcqf04JbS3ENLc+FQynumqsAlejLBBf2zNBzjclNGIUfmfqPL
         RqZDeQDywWt2a+6CcoAw8Nfh2xvTN9rzHYtIb0D1qBPlcfTjswB+3tvRKeE8XvWoC0n7
         aOD96tIehSyyhhw7/ZGK9bH1inWhU8ea3JYphVJ8n2BKzGpayDAeyqmT3BnVnUJdcrIb
         IxnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=mV/oM0ZFOSmZTr1tEI8al4WRLOksCnyDL+Y/DEXpI5s=;
        b=DUajq6exHniPJJwXYjvZByBlxdU7LYx1yudIYIZtsjZNSq9wQ5rPYZ+uGPdE03JiRR
         UBGtfA+WGkjZZz6RRoHR8oJtcpien0MErmHwr6HPuPWsToX5ZKuDpJ0wuvyiFHbm7R9Y
         sGhLiObaF5qjt/XJwSnTsvo5S/0dvbsAetHVHsRUBZGlxnix9a+mq6Jm0T3+PZWdSZUh
         S+iz9dYBKRigJZt+buBMRBqKh1Fcg6L0Y8eX3X7gHwYQruV+aL21xyOVZ54u3Q5NWoSj
         avrkk0DNPpAV5jnK1YHFkVtnOX1pNWHrPm5LG407ZiD94dBH5PLabyR9NNYyo/mO2EFJ
         fWyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UpMGEnz8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id h3-20020a05651c124300b0026df6ec3a3csi274974ljh.8.2022.10.06.09.24.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 09:24:45 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 449B31F8C8;
	Thu,  6 Oct 2022 16:24:44 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0561F13AC8;
	Thu,  6 Oct 2022 16:24:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id dJZHAUwBP2MOIwAAMHmgww
	(envelope-from <jack@suse.cz>); Thu, 06 Oct 2022 16:24:44 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 7D4DEA06E9; Thu,  6 Oct 2022 18:24:43 +0200 (CEST)
Date: Thu, 6 Oct 2022 18:24:43 +0200
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
Subject: Re: [PATCH v2 1/5] treewide: use prandom_u32_max() when possible
Message-ID: <20221006162443.b66waqsxlntfeoek@quack3>
References: <20221006132510.23374-1-Jason@zx2c4.com>
 <20221006132510.23374-2-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221006132510.23374-2-Jason@zx2c4.com>
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=UpMGEnz8;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning jack@suse.cz does not designate 2001:67c:2178:6::1d as
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

On Thu 06-10-22 07:25:06, Jason A. Donenfeld wrote:
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions.
>=20
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: KP Singh <kpsingh@kernel.org>
> Reviewed-by: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

for the ext2, ext4, and lib/sbitmap.c bits.

								Honza
--=20
Jan Kara <jack@suse.com>
SUSE Labs, CR

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221006162443.b66waqsxlntfeoek%40quack3.
