Return-Path: <kasan-dev+bncBDQ2L75W5QGBB6MR52YAMGQEKV3Z5RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B0C858A4100
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Apr 2024 09:42:50 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-36a0f8a2f3asf995645ab.1
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Apr 2024 00:42:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713080569; cv=pass;
        d=google.com; s=arc-20160816;
        b=fpW508ElP91HTaQV4SdPDDP2hmYw0HPNit4KZuzAZPweRn1UCjsXt6h1wh92sUOKAc
         9I1mxyuhWdksU4NPY6GdqjQvtUelR5tP1ZjNEsv71yqWNKykmSTUET1bx6YvYKvkgGFs
         QeOQOigETCQ7LIP+kwh82mT/r32Hr5Mgfmvr5UU+phs9f+Ev40ArqhUU0I0btTnYEDme
         hmr3ryKkED1QQh0cJYvGESTM9a8PtbZn7zI2ig9kuoNXfS3TeEwRPPfJb69K3cAXZqus
         AYok9QE7asEwYIMiaC7hF4hTra9LpG24ZbXwKU5mIwoNFRe8FG1ej6soC59iq799lE7k
         74vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ub2mm47iowfJ7TWAgocdGM6ebGv1h0ADfjUtbyHxcDI=;
        fh=Qq6lbJU8dBQM7ajilQHH/u8GwXjzmE0CW177/uMOZU8=;
        b=eN9MvPzBZKsKrFTBvc2VCZa2bf2wZnUPIehiR1RzUINH8j3OC4CTJaU9hfYNClK+AJ
         FJwaFiIiEbisA5HdUE84DpXHMFRMsqZC0TXY+KWVmakwI+Baj8hB4k7F6dyGZcaCWhhH
         rOu7FINWrk029/D7NA/Wvzvrp5Moz7ll9rmWN2jnpCyOukpJkDK9BN2dE105DEAnCNOb
         yoXQixe5h7IFSK5VPu1YF+kn2+TR7vpVHlJfnOEcy+kLC9qjkDHAlF26OVuH24az5A2l
         22cPcbIZmAKO9OslC1UkVyPVDWvV0YrcvxzgYTY78gsvFqcwJscbqLyaRSfR2rdM9aBp
         vS7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NsmLywl4;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713080569; x=1713685369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ub2mm47iowfJ7TWAgocdGM6ebGv1h0ADfjUtbyHxcDI=;
        b=Sc5UXrDybXKOapKIQzVpPCRxAgjRICju3GJrvIMDUf3uDzD/TLRB8N4tBohqvg0Fhu
         zu8iPoqRkskk+Kxwp6uo/sRjsAeT5iKgSDorguZ6CuCRuzSagDEsFoxns4EK7eJ07kvs
         MTxdHa8+Zo2tBolW2qk4Wy9j8doQWPLZfhrkJIDptuvIbYr1AHb1p8Z5UOQPND+AQ2CW
         rx1OC+tg0uv7is0Ky15/qUGW/cTMua1oyOuEFEEkt77CZhbqXOgfc1PghLf7veHLpmTY
         7EERNm0U64eH9poDnDqZmh6D8fcbIUwLfR87vwznddmLfIIZiggkThZKrlTL0rbLrFWO
         yYZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713080569; x=1713685369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ub2mm47iowfJ7TWAgocdGM6ebGv1h0ADfjUtbyHxcDI=;
        b=ZjcEW6sEaH5wWtr+8Sq5ZOJGDJsci8e5KY1+tyHiNYAE0D/QOsMjy6dgzD3R2bDxeI
         pyVfHA0t7/lTWmAH6Ox81a+rLua09R2oqNaUaqoTRS+a0XYBlorVCNpA4sRE3daamsMv
         j3yIw1fzJzPsq9zcHh6/7M9UulehbSSp41/Yq1PtYBbG+eHCUE4qNKHBsF8jN9eVv4WR
         4f0AzlmFzjF7WHMQuu43EbI+SLAobqo9eNSTe152B9Z4+B/oE0mArT8hZCoCM6wb2o46
         RAcbBoMBBElrV5wdqDkckrPdaaeSAqWHVYY2jLVQ0i4QE/fNPIDPM447hqn/LJWFpxlQ
         e3Jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKas0IzGVFx2NnrmxDn+k1aJl54Z7NTlsTCeWXASCWruzw82WbxvoLx6bpmCnYtbw6Vw7WGd/2qJdu80r5X+kpR0i99LeXOg==
X-Gm-Message-State: AOJu0YxgnJWtLv3w7NR6JqvwQ+q6/XnPA5nc6MeC1fCs9hzsB4DU5w0d
	C0m593nycYKaxH6EZbPgb6coU3gLiAh89eLHqEgkfI6RKiEptRPC
X-Google-Smtp-Source: AGHT+IETKqLs5NgnfiP4thoj2AuY2bR8+jxRJMaAdICv2KAsm2047FRgy3uO4ruR+Kh7DL8/sD+2yA==
X-Received: by 2002:a92:c54b:0:b0:36b:ff2:4189 with SMTP id a11-20020a92c54b000000b0036b0ff24189mr237505ilj.29.1713080569262;
        Sun, 14 Apr 2024 00:42:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c109:0:b0:368:589a:3ea0 with SMTP id p9-20020a92c109000000b00368589a3ea0ls1598582ile.1.-pod-prod-04-us;
 Sun, 14 Apr 2024 00:42:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4mK/U88WOYw1GcIKBIi1L7tVQyL4papTxgB+0UdXk4dA5F2Pr2bSjFbH/T+ioKep1hJBSLvoDlZdpXqk2MTVttBDHRjlszr3wkA==
X-Received: by 2002:a92:c541:0:b0:36a:1725:e123 with SMTP id a1-20020a92c541000000b0036a1725e123mr8946356ilj.14.1713080568417;
        Sun, 14 Apr 2024 00:42:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713080568; cv=none;
        d=google.com; s=arc-20160816;
        b=FctiXNBgwPJo3T+1uAk18H5MAnHDFzwbqn9PqMEc5Fsc+RIylogAkCt8grbWPsep5V
         OczCt4Sx6nZP6KgpzfIzQPrQWYayL29EnPKqiHlJAuDxAh92NHE26Bhg31FJ/wfy68J3
         UWrlRlkyihOxsoa0AgOfqWo8gVes06BdXilOCdBNVumGzM0bZ+jW1nC/16rL1Pn81XOj
         RZuySvokr6GrWGGkgnWya7M3jDqrvDQDHybvyfIPsrqPcS/gZeXzDBDos97TW4r5GebI
         9gRKDpbVexGa2/3erkGNI5hXxMMhqstpk89td2IOczGaN/ncFSJBqn/Xcqale7SdGCkA
         rfSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6ykjIOAiBTxAiHLB66C2NCpr8txrh6E+cO0uOmmMD4g=;
        fh=fmJAQNqzv5Vyv75RDDlN7CK/avNDzxUCRrx53jU3DTg=;
        b=WHydNNRAo+e1nIaUR4o50lwTTOTGkYgrvikjb/xZPUyflKeGOawRdPyKD3zy0PeECb
         WCHD2JNHG+FZeRnq9BZCBS76kcXE3UvQ1BcXSNtWN5+KVQ3wHDXXKAdpVfXoG/HoLmvp
         ZbEeNdbORJecMigy4xdRIOpPLoRIa6bB4luFK37qHvUYOAKBjJrS8c27CpL2Ai/thbWu
         nljAFTcR/WqRbwpsKKvjftf/rMqG67Us/Kmt8Dy8FAzzr1JhtE3fMK3rrkeR+YzonYAO
         7r8/+Vtbqb7LDeqKjyG2QnEGB4mmf2gljnvDThHhDio2jAU9tutNnCW1eX+rsvXTywzf
         GkBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NsmLywl4;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id p15-20020a056e02144f00b0036a2da4fbf5si490557ilo.1.2024.04.14.00.42.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Apr 2024 00:42:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id DFDE7CE01C8;
	Sun, 14 Apr 2024 07:42:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CB96CC072AA;
	Sun, 14 Apr 2024 07:42:43 +0000 (UTC)
Date: Sun, 14 Apr 2024 16:42:37 +0900
From: Mark Brown <broonie@kernel.org>
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests: fix build failure with NOLIBC
Message-ID: <ZhuI7TRZ111I3mBU@finisterre.sirena.org.uk>
References: <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
 <20240412123536.GA32444@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="RDirHntfewS0PWXo"
Content-Disposition: inline
In-Reply-To: <20240412123536.GA32444@redhat.com>
X-Cookie: You might have mail.
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NsmLywl4;       spf=pass
 (google.com: domain of broonie@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass (p=NONE
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


--RDirHntfewS0PWXo
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Fri, Apr 12, 2024 at 02:35:36PM +0200, Oleg Nesterov wrote:
> As Mark explains ksft_min_kernel_version() can't be compiled with nolibc,
> it doesn't implement uname().
> 
> Fixes: 6d029c25b71f ("selftests/timers/posix_timers: Reimplement check_timer_distribution()")
> Reported-by: Mark Brown <broonie@kernel.org>
> Closes: https://lore.kernel.org/all/f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk/
> Signed-off-by: Oleg Nesterov <oleg@redhat.com>

Makes sense to me given that there's not likely to be any immediate
users.

Reviewed-by: Mark Brown <broonie@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZhuI7TRZ111I3mBU%40finisterre.sirena.org.uk.

--RDirHntfewS0PWXo
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmYbiOoACgkQJNaLcl1U
h9DjfAf+NeKWvpY1kfNztkGXC5XgmSPRN72mmjwoz5S5ADSj6eACj6FVUx8dMLmx
MboAtU5eBumh83kzmDd64LH3zoNrC47WBOgPc8DNJ+Rojo+M1+9wA1EnC0qbPQyT
0H4LAFT2+/erlxSCrXcI/ValOLvD7+OOlEpObFMbFzyCT3cLQhQe/7o1gkjvArBC
Y39UmP6cvV69IhQ0VRg2F+xvOZTBrD4h2THuRwD6FXnMt/kYfcKpFO0BeB+XvbvV
r+7KTIQ8fkxw19JNuwSpzOM7M1Y9gJcsyN+bIZf1ctwOullXzAv2hh1IruVehXfA
Ey2qL/O9t3pwtZT3MddpQbx8KoJpAg==
=MeqW
-----END PGP SIGNATURE-----

--RDirHntfewS0PWXo--
