Return-Path: <kasan-dev+bncBDQ2L75W5QGBBRFW36YAMGQEJO7ULPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97D128A14DB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 14:44:54 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1e4c75eb382sf22880185ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 05:44:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712839493; cv=pass;
        d=google.com; s=arc-20160816;
        b=VWlFFa3nYzLoubwriEf4OJXWFT/ac0z/rbYBoDZdLlPVGEKmM2MEqFa9fc0hDDO4Ey
         5UgrpPlGE9YrU293UNl+q/J8GQwwa2u9Wt4MtbnzxKkWAHtYGHLU93trJpYHQDg5izgJ
         HaixD3LT1AP7XXtbsQKsq15WFhrRwcDxzsZE80OpYzUM0aYAeURVScz8Dvg/2fSUjtlB
         N6kdxPse7AANUAXItHLrdxWWC0Zt1SUKHUHyrsXU8bfEFg1mrzsuUw92cMVcoPd44qhH
         w5jvKFCQ5+hrH5XXLWPBdFd9cIplh63fdwLDM4UKF9A39lcHnBBjPjkNcuH2jWCm3vfA
         Rq0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RoCMyjyaEuUJWcMhTsVz1/Yvi7JqKsvh6kNgh3fzgBA=;
        fh=iZ9QyTHrwd0pa8m6l7L4wKrXH7MJ+Lrbe7asgpsQ3ks=;
        b=LQxiX79Ig0ebjEAxCjyVY2We6ZMioJ4xHkSSzLuiTQeLqodXNd7L/8QJogRmHTIpiK
         ByDd8zhB/8pd53XpeISQ6kwCxZHg6TjjGWlnz6VeTJMmI+C6yyoq1cyJVFIyX3j9O6Q7
         OklSuOjmHOz5lWvPEYCM6nm32C/ss67bp6M8vbUDY8lwMVX568C5hGDOgiiq1j2nvoi1
         aYaNgFiDa+LU9Nkiy6G0ehiDdTIkMJyPIMDNCq2EBXhuoA4+4IwyKUOLg0VA5Uvt15Su
         jt4xeR+zYAMc1XeWXVbrOyM8lX+b/XYV0FUdKdYFDh9MPC77oZadvAAr8GvehKKn0qt4
         asnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ezO8dL3L;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712839493; x=1713444293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RoCMyjyaEuUJWcMhTsVz1/Yvi7JqKsvh6kNgh3fzgBA=;
        b=p+gKFgq4MdLZpJ4Svy8jfdyxDLn8HCX9PlzpHnIcnjYHPEEi3pwMqalr4H0TwE5OYF
         YD2Ni99gIRfBzaVtsos+Li/3L3SEdsx7HuuSSrMBRKuomlg9VZWk6PKLFGIqjF5zF1Yi
         tiKmOk6MSwMWrxZqG1q3fG6zJ0grBalp310lAaoyKCstPgaEAPauHhkmgQxZLah81Tw/
         m+jSp/aGtAGJl+tEduEnsh5KvIFF2Z4WlPHQYt3zsGQTCEP1ZDFHKX9TMahMXJZBXZoR
         1p7i+TEYjyFJt56EmoPtxrcj6Ybua18nyxBwQ15lwKQdytqqmwj1vwCJvobzKd1G9ZY6
         2Ozw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712839493; x=1713444293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RoCMyjyaEuUJWcMhTsVz1/Yvi7JqKsvh6kNgh3fzgBA=;
        b=asHvcutud5M+sxQ1sbr2e9f8XHoFH2owfLczOUZJ1bHHru9fRFw0qv1GiPzGSZrj+/
         siV/P+V4IVL3p52tEojOPLIddZ3dwa65sGVBnM+Gh0EgPi+NJ6qtpYKoAqFZCOkewo/h
         xE5ViJzh3G0upS/wE5cGIw+HcwnjchhPdowJT0mOs0e4oey2G+UjhaqzSC9TiWCBO0vQ
         n6/MwekkLq5HJwNjUK6X7Z+5SUlXB+zYX0c6ip9PEHN+hO3BcuvL6z19U67MCnRk5MPv
         g/YvbYv3NaeGdzEvT8dHLF+baunL/J4arwYExjy79dtn0bW8hKBYRyIj16w8NLwIl0nx
         jqoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFZK0m9FFbbsNU4Lt7IwNuH/8bf2AjY96qZ/7UZ4TDZu5mcVvkRe9ZWw4sAAJsN/Fsa8w8zNJguN276ks3C/FgKAJLBoSc0w==
X-Gm-Message-State: AOJu0YzmNYOs9ns8Lhj137S00t2cvq5pcioycCTuDYpzALKdjMGsK08K
	bH4m9eu/L86Khb66eP5v4pjW/n6DBTSngUL6imEiE3J+CcAU2ex/
X-Google-Smtp-Source: AGHT+IFiSm+RX76oZ9l5KFeX49rQJ09wF2d+s7E2I6n6k6GstPQ9lTA2W2lUgTCFwrBKOJF6S2GwSw==
X-Received: by 2002:a17:903:98c:b0:1e5:58ab:1cb3 with SMTP id mb12-20020a170903098c00b001e558ab1cb3mr1424975plb.22.1712839493049;
        Thu, 11 Apr 2024 05:44:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea06:b0:1e2:45c6:efb with SMTP id
 s6-20020a170902ea0600b001e245c60efbls5268955plg.2.-pod-prod-04-us; Thu, 11
 Apr 2024 05:44:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLRRBSWFSVBtuzkTmmN85ebtoK8FfBA5CnIKc4jayrc1OQBslLmKAeKmn9iIPvU4ywPx5FJThLwjeS9fkUjdhEUPz9YSZiIU3eVg==
X-Received: by 2002:a17:903:240a:b0:1e5:31c5:d7be with SMTP id e10-20020a170903240a00b001e531c5d7bemr2868456plo.40.1712839491648;
        Thu, 11 Apr 2024 05:44:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712839491; cv=none;
        d=google.com; s=arc-20160816;
        b=Br7lyx+G0SRVz/3XHtxQdkz+9izBJ3KBER4pCncqnTB+2yAso2pPe85VkilVKXlUxn
         0YM3cuObiBEr6LKrxVihIUkoxDzW3PNVcXjEvkiefXnwfkWIzZ5yZ/vySY5Q+W0XCjYU
         63I80Y94yNLN+Ai7hJra9gIDkFLoT4IFBU5JggK33gXvJauCArDNFWzW9xj3v6f+3py4
         BwORRZVwxpP9V37zDAJBEDiwAixJydLhC38fgAPIEeOyTgyg5WyG205C5fD5Iu7CErZC
         x6sZUE8lS0W7cSb/mErMFF6bIl2YZkMKE92s6zoV9hpMQADNBdgJ/NDcJbfzw+Az1coX
         uNhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6mucKL7w80LKy7OOJbQ0zcC8h92HVDGbXTht5vx07EA=;
        fh=fmJAQNqzv5Vyv75RDDlN7CK/avNDzxUCRrx53jU3DTg=;
        b=IZjGjvOyKzHxYa5VFwZRAfiVADIENAGjQWMmtcuQbjT9sabq/H3wNIWvrtqXwm06fI
         bKgDw1rr1AyA8Ouw/AeRXuwBQUjb6ZlDwxvu2y2q2VP4ARuMyIuFonKTP9R46zHtmITP
         gsNaMCTfstZptzCYmniCia9kYl77DFR7BoFNzz4XgOUkGFuNX9OM4Nitupm5SGLkFvRI
         1j/8sHRalYrxnCjivT5Jb/XAdId7hrzSm9nk8LDWFx3DazP82mwEiojMwh+UbRrN9c48
         PCbmdBU6G08VoSb050t3aGogBlgB7jdMCv9lwa4RHVN5aCGpmHuL7sI3Phmy+p8h/A+U
         z0Og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ezO8dL3L;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id ld15-20020a170902facf00b001e24b3e3be3si77394plb.4.2024.04.11.05.44.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Apr 2024 05:44:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 74579CE309F;
	Thu, 11 Apr 2024 12:44:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A944DC433C7;
	Thu, 11 Apr 2024 12:44:45 +0000 (UTC)
Date: Thu, 11 Apr 2024 13:44:42 +0100
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
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="eLEudqFzuEINegTy"
Content-Disposition: inline
In-Reply-To: <20240406150950.GA3060@redhat.com>
X-Cookie: Elliptic paraboloids for sale.
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ezO8dL3L;       spf=pass
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


--eLEudqFzuEINegTy
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Sat, Apr 06, 2024 at 05:09:51PM +0200, Oleg Nesterov wrote:
> Thomas says:
> 
> 	The signal distribution test has a tendency to hang for a long
> 	time as the signal delivery is not really evenly distributed. In
> 	fact it might never be distributed across all threads ever in
> 	the way it is written.
> 
> To me even the
> 
> 	This primarily tests that the kernel does not favour any one.

Further to my previous mail it's also broken the arm64 selftest builds,
they use kselftest.h with nolibc in order to test low level
functionality mainly used by libc implementations and nolibc doesn't
implement uname():

In file included from za-fork.c:12:
../../kselftest.h:433:17: error: variable has incomplete type 'struct utsname'
        struct utsname info;
                       ^
../../kselftest.h:433:9: note: forward declaration of 'struct utsname'
        struct utsname info;
               ^
../../kselftest.h:435:6: error: call to undeclared function 'uname'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
            ^
../../kselftest.h:435:22: error: call to undeclared function 'sscanf'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
                            ^
1 warning and 3 errors generated.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f0523b3a-ea08-4615-b0fb-5b504a2d39df%40sirena.org.uk.

--eLEudqFzuEINegTy
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmYX2zoACgkQJNaLcl1U
h9BNsAf/SALLRc/9ZAS59tFpxQdRfvXtWqUNgZWj+IKbEwArKB6V0kOSkYeeFF5x
cIP8785Nor1UFY6gBKpNdXwyI1zCLIpX+RwrV2aFJ/DQlcnLfCXvYlPIJ4hVV3DM
LTDs6/MtMx7xXkbyfXRyw+Dy0JuoW7m5l982y1KGI8otoA+Ld/hgbnamNRfrIWd4
GTCAup3fO84OA892aV4hmGgPFHjRuXvCwHg2LLrkFiaGpn9Qz2iJkalIYimZQtuW
sXpV4urnzUybTmMXPRWhj7znL+5BYVPXO83ZtfSq6/jJ60Md5Tg36aazNXpo0H68
OCJR4L+iK4CHAj87DoDQkhVw2BRaUA==
=tp/A
-----END PGP SIGNATURE-----

--eLEudqFzuEINegTy--
