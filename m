Return-Path: <kasan-dev+bncBAABBVU3U3BQMGQEDLKJ45I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D5E85AFA1D8
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 22:40:56 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b362d101243sf1260556a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 13:40:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751748055; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wb8Hcw9sWhRYSynEoUmUyMy+clHDFHEioQK+lgYp1DO7Vfit1QPq5Ru8NvOz1Wz533
         xkwoEj/sx0tC09RtVQ1IsbYtCgzhZIXd+XEI44xAmctTS3VfWrE5bWRkj+DzFRW0BXA4
         ypAC7r/1gnIR4Zb2rTFWUkGg2u+4heHLMjyoc12jNxzfkSH8ZOpOeQpa1Nl5iWzVly2o
         CCTxnpvI1GlhfGDpFadS4ExAUQ1mxHBrx27Av0FwXt9ozN5Tck2MwgvyH0n4tPFJMAqp
         L7X4L0c6aRoNrwSyozX7eD+24vCYhqgFnELDJV5x9KITFjbqiKPuoxnKmbBBWVAOGMai
         KigA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VphfVG3t/jd/YleNEffIK68GRgRGJw341mXQWtlCLcY=;
        fh=OBC9tAIfKyxulz8EQ8DDG8dUboXmlOe/lio6PgEQQPg=;
        b=Xpn6oM9XNxEo8HH1hCMw5DnNxQqTxjCTIZeWZI4RrgWi/agtXzSQkPOFTkkJhVKz34
         qNCsoP7RpYcKXh1ntYJ74drO1NnmatUI8wijkOUzmbDy0E5Z58gW/BXvpVPJrcEElUH0
         S1x/k58P1fckIkprk3M8HjCYdrc9Rkkf5D8GbzrWmDxTz9zZ3dZ3VSivdwuLQ3OKYqj6
         UGDOkVYevB5Yydt7MdcQVwUhT0jNdsHNHHDa6m0kJJvJx/NLTAY3YdPTss1wk7p+vGV+
         CList6Qd/5dHhfGXcjhhHa1JkC9y0NzomTTSpQfAh/zFRKChCgM757b4YwkOhOLQ8fNr
         AQRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WgrxJfBR;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751748055; x=1752352855; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VphfVG3t/jd/YleNEffIK68GRgRGJw341mXQWtlCLcY=;
        b=tFtTiluETrD194g5yI7lxyM8lTZrFYlroVeytWUc1g8TIWstNUUlsK8mKAXpXH6Tio
         FlEifiCXlmgOu1WEDRqmGTwECD0mZoESPUCuNamd1T8GPkMitTRC+KM0ORT5A7V0lwBf
         64b2lvc0HmlNDtSt7hvRpA1QWoAmzodVtyprA4CswaopkEtx2btVJcSkrJbgz6Zndp3n
         //N4RJmK+oKlBYu6OYpKtDOu/LJaXBU2c0oxVQwkVX9DqA/kAolV13qvYyNZhibkENsG
         3T6DwUJybv4yl3WLU1b9gP+IaubKkhinzjZKIb2v7YPID6NsJ8u4Mee9HewV7bSFV8Bi
         r3Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751748055; x=1752352855;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VphfVG3t/jd/YleNEffIK68GRgRGJw341mXQWtlCLcY=;
        b=FCh5A+lrlttceabUv4LLP1F1x8P36dIVND0Iu2F+cacQ/Faz5eTtPJzDIQDlwWAsSz
         3htJwqJEBeEO7aI9hvWk1Hr5VrI4qFVUUZGwAFhopDf7iRiDcNNh8OAJkPnySFFYWLX7
         B2RMY3ghMp7G55QWueeHLx/ortCqUe8UlWZR/CKTjRO7pVzOfrudmAfX3l21J60L9CG2
         QQF0g9Axg7X+U7/IrdVoV0zEKuFQat6FSKFbgoVFbN32ryNrLC8+GQX0DExdHuQmqL3j
         vGz1urmeyoYBDNxdL7qAcqNUpfd7BH1sEgBzalJvYrDj6+zwhM4TftoT2zueQVtMBxwM
         GECg==
X-Forwarded-Encrypted: i=2; AJvYcCWtj5V8+EqQutsAVx/VCz3Ttbjw1W639zDesWicT9Th+IWqYocrU2cDV33cR1Y9pf9nbLWXBw==@lfdr.de
X-Gm-Message-State: AOJu0YzLr1MZDAgj9Cj7Au6sPDZ23NBqZJyDXmkziIu6gk7WnQ53CCKo
	koV+ApNAdSmvBF05EL9h2mYd1CeTYPQSC76cZt9vu7kdzwBdnV7o+S04
X-Google-Smtp-Source: AGHT+IH3fEX3nYMn9NLLxtjs/AV8r4xQeYK09TaNaOPivL7tPGJ5tbivnXF1M9QafbKdh83jHY2fFQ==
X-Received: by 2002:a17:90b:584e:b0:312:db8:dbdd with SMTP id 98e67ed59e1d1-31aadd9ffccmr9796584a91.28.1751748054672;
        Sat, 05 Jul 2025 13:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNUiz4HnwYJ2zJxZyC5+zT60MhoF1vnRYc8FTRtC3faA==
Received: by 2002:a17:90b:2bca:b0:311:a98a:8493 with SMTP id
 98e67ed59e1d1-31ab035c8fdls1042224a91.2.-pod-prod-09-us; Sat, 05 Jul 2025
 13:40:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjYymWpqkmMm49Yf7V/kW7On6jHc84pOaPFsor85+8GLoCvweMT7ZOs6PAP9nWKrq+4RBs6PE0mMY=@googlegroups.com
X-Received: by 2002:a17:90b:584e:b0:312:db8:dbdd with SMTP id 98e67ed59e1d1-31aadd9ffccmr9796544a91.28.1751748053473;
        Sat, 05 Jul 2025 13:40:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751748053; cv=none;
        d=google.com; s=arc-20240605;
        b=Ph7qeo5plDuCEDsRAnq6pfIOhOfH29Pa/JmD5l+T/aUk4zir9Esqd2HzDbG4RR722C
         JdTttwrWcl9GoZ+Vdd7ZQJSBufqc+M60FpaLkLUh7BeaAySXX8VO6Lk4y3V64wbkwf/B
         Xo+BUucx9qzfsN0pM38OXgh7Vt67y9oDM42/0Nt89iESjRXIg54a+3vFBOmFIguEtvPs
         Q2sNk7RDvFgH2ZFvTxC+3a/z5l1HCjGwJXF/f+5ID3XFYIO+suF/Eh+CK8Bal5b5j5VK
         DdKSF1hXtTQ+HxXWmtGmpaqL7IBo5ybJk0+H4rdhR0MW7/MN+ASG4tHIKo9kv3He2bCG
         1ntg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wB1AuKwBi60IwzCfLiylrHXBpKT2zT7u4DnAFQn2V08=;
        fh=ymshoAxJ0p6GN3p3j82MEvHzKhZuKEztLOFFE4Sbfe0=;
        b=LBGp24C0bEHzYR4TewFI0g1/EDWVBvWiOGV6jbc4l++3keNTTM3+78NvCDrA4CDMdZ
         dPQSlg0wCK475vdboVMYryAe4AVosR/DYbbw6KGk8NyC5k4HY9UqlDEfLsjeSx9ah3Xz
         Kl+de2Be6u0Us/VT/84V026Yh0baxfDbWQxIAEGMaGlHAmYFqY9tDSCDoIS/YGEhp7S4
         C/httbhUynoeOlfYujpegPQtTtsmRErZP3I+J+bY+8dYnptGXb7TEz5qR50wU3eig/k+
         7PD6nqQLqyHsSHGoBcOfryMLz1O/DkSfLkM2v+noJ1h+niKiP/M1L7rMgsYNloSypZWg
         SN6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WgrxJfBR;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c84505cd9si1960765ad.8.2025.07.05.13.40.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 13:40:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 69E1361155;
	Sat,  5 Jul 2025 20:40:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 39231C4CEE7;
	Sat,  5 Jul 2025 20:40:51 +0000 (UTC)
Date: Sat, 5 Jul 2025 22:40:49 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
Message-ID: <nx6vj5qqcgkts4pmefzux3ee4kuumwyjh6vlwsdltf56ayq33e@kyf25zkic2rk>
References: <cover.1751747518.git.alx@kernel.org>
 <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="pgtmvcnqaimzwfi6"
Content-Disposition: inline
In-Reply-To: <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WgrxJfBR;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--pgtmvcnqaimzwfi6
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
References: <cover.1751747518.git.alx@kernel.org>
 <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
In-Reply-To: <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>

On Sat, Jul 05, 2025 at 10:33:49PM +0200, Alejandro Colomar wrote:
> seprintf()
> ==========
> 
> seprintf() is a function similar to stpcpy(3) in the sense that it
> returns a pointer that is suitable for chaining to other copy
> operations.
> 
> It takes a pointer to the end of the buffer as a sentinel for when to
> truncate, which unlike a size, doesn't need to be updated after every
> call.  This makes it much more ergonomic, avoiding manually calculating
> the size after each copy, which is error prone.
> 
> It also makes error handling much easier, by reporting truncation with
> a null pointer, which is accepted and transparently passed down by
> subsequent seprintf() calls.  This results in only needing to report
> errors once after a chain of seprintf() calls, unlike snprintf(3), which
> requires checking after every call.
> 
> 	p = buf;
> 	e = buf + countof(buf);
> 	p = seprintf(p, e, foo);
> 	p = seprintf(p, e, bar);
> 	if (p == NULL)
> 		goto trunc;
> 
> vs
> 
> 	len = 0;
> 	size = countof(buf);
> 	len += snprintf(buf + len, size - len, foo);
> 	if (len >= size)
> 		goto trunc;
> 
> 	len += snprintf(buf + len, size - len, bar);
> 	if (len >= size)
> 		goto trunc;
> 
> And also better than scnprintf() calls:
> 
> 	len = 0;
> 	size = countof(buf);
> 	len += scnprintf(buf + len, size - len, foo);
> 	len += scnprintf(buf + len, size - len, bar);
> 	if (len >= size)
> 		goto trunc;

Oops, this error handling is incorrect, as scnprintf() doesn't report
truncation.  I should have compared

	p = buf;
	e = buf + countof(buf);
	p = seprintf(p, e, foo);
	p = seprintf(p, e, bar);

vs

	len = 0;
	size = countof(buf);
	len += scnprintf(buf + len, size - len, foo);
	len += scnprintf(buf + len, size - len, bar);

> 
> It seems aparent that it's a more elegant approach to string catenation.
> 
> stprintf()
> ==========
> 
> stprintf() is a helper that is needed for implementing seprintf()
> --although it could be open-coded within vseprintf(), of course--, but
> it's also useful by itself.  It has the same interface properties as
> strscpy(): that is, it copies with truncation, and reports truncation
> with -E2BIG.  It would be useful to replace some calls to snprintf(3)
> and scnprintf() which don't need chaining, and where it's simpler to
> pass a size.
> 
> It is better than plain snprintf(3), because it results in simpler error
> detection (it doesn't need a check >=countof(buf), but rather <0).
> 
> Cc: Kees Cook <kees@kernel.org>
> Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
> Signed-off-by: Alejandro Colomar <alx@kernel.org>
> ---
>  lib/vsprintf.c | 109 +++++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 109 insertions(+)
> 
> diff --git a/lib/vsprintf.c b/lib/vsprintf.c
> index 01699852f30c..a3efacadb5e5 100644
> --- a/lib/vsprintf.c
> +++ b/lib/vsprintf.c
> @@ -2892,6 +2892,37 @@ int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
>  }
>  EXPORT_SYMBOL(vsnprintf);
>  
> +/**
> + * vstprintf - Format a string and place it in a buffer
> + * @buf: The buffer to place the result into
> + * @size: The size of the buffer, including the trailing null space
> + * @fmt: The format string to use
> + * @args: Arguments for the format string
> + *
> + * The return value is the length of the new string.
> + * If the string is truncated, the function returns -E2BIG.
> + *
> + * If you're not already dealing with a va_list consider using stprintf().
> + *
> + * See the vsnprintf() documentation for format string extensions over C99.
> + */
> +int vstprintf(char *buf, size_t size, const char *fmt, va_list args)
> +{
> +	int len;
> +
> +	len = vsnprintf(buf, size, fmt, args);
> +
> +	// It seems the kernel's vsnprintf() doesn't fail?
> +	//if (unlikely(len < 0))
> +	//	return -E2BIG;
> +
> +	if (unlikely(len >= size))
> +		return -E2BIG;
> +
> +	return len;
> +}
> +EXPORT_SYMBOL(vstprintf);
> +
>  /**
>   * vscnprintf - Format a string and place it in a buffer
>   * @buf: The buffer to place the result into
> @@ -2923,6 +2954,36 @@ int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
>  }
>  EXPORT_SYMBOL(vscnprintf);
>  
> +/**
> + * vseprintf - Format a string and place it in a buffer
> + * @p: The buffer to place the result into
> + * @end: A pointer to one past the last character in the buffer
> + * @fmt: The format string to use
> + * @args: Arguments for the format string
> + *
> + * The return value is a pointer to the trailing '\0'.
> + * If @p is NULL, the function returns NULL.
> + * If the string is truncated, the function returns NULL.
> + *
> + * If you're not already dealing with a va_list consider using seprintf().
> + *
> + * See the vsnprintf() documentation for format string extensions over C99.
> + */
> +char *vseprintf(char *p, const char end[0], const char *fmt, va_list args)
> +{
> +	int len;
> +
> +	if (unlikely(p == NULL))
> +		return NULL;
> +
> +	len = vstprintf(p, end - p, fmt, args);
> +	if (unlikely(len < 0))
> +		return NULL;
> +
> +	return p + len;
> +}
> +EXPORT_SYMBOL(vseprintf);
> +
>  /**
>   * snprintf - Format a string and place it in a buffer
>   * @buf: The buffer to place the result into
> @@ -2950,6 +3011,30 @@ int snprintf(char *buf, size_t size, const char *fmt, ...)
>  }
>  EXPORT_SYMBOL(snprintf);
>  
> +/**
> + * stprintf - Format a string and place it in a buffer
> + * @buf: The buffer to place the result into
> + * @size: The size of the buffer, including the trailing null space
> + * @fmt: The format string to use
> + * @...: Arguments for the format string
> + *
> + * The return value is the length of the new string.
> + * If the string is truncated, the function returns -E2BIG.
> + */
> +
> +int stprintf(char *buf, size_t size, const char *fmt, ...)
> +{
> +	va_list args;
> +	int len;
> +
> +	va_start(args, fmt);
> +	len = vstprintf(buf, size, fmt, args);
> +	va_end(args);
> +
> +	return len;
> +}
> +EXPORT_SYMBOL(stprintf);
> +
>  /**
>   * scnprintf - Format a string and place it in a buffer
>   * @buf: The buffer to place the result into
> @@ -2974,6 +3059,30 @@ int scnprintf(char *buf, size_t size, const char *fmt, ...)
>  }
>  EXPORT_SYMBOL(scnprintf);
>  
> +/**
> + * seprintf - Format a string and place it in a buffer
> + * @p: The buffer to place the result into
> + * @end: A pointer to one past the last character in the buffer
> + * @fmt: The format string to use
> + * @...: Arguments for the format string
> + *
> + * The return value is a pointer to the trailing '\0'.
> + * If @buf is NULL, the function returns NULL.
> + * If the string is truncated, the function returns NULL.
> + */
> +
> +char *seprintf(char *p, const char end[0], const char *fmt, ...)
> +{
> +	va_list args;
> +
> +	va_start(args, fmt);
> +	p = vseprintf(p, end, fmt, args);
> +	va_end(args);
> +
> +	return p;
> +}
> +EXPORT_SYMBOL(seprintf);
> +
>  /**
>   * vsprintf - Format a string and place it in a buffer
>   * @buf: The buffer to place the result into
> -- 
> 2.50.0
> 

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/nx6vj5qqcgkts4pmefzux3ee4kuumwyjh6vlwsdltf56ayq33e%40kyf25zkic2rk.

--pgtmvcnqaimzwfi6
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhpjcsACgkQ64mZXMKQ
wqmVzQ/+KqUYH2RJ6XCFWIsqgzQlHWhF5QOxlPi3CwpP/HjdGT+EmXEM1eNot1aX
OMIiUD26IZTG9icnCMdPoUXUmIQ4k5GalCWxTP8iKbwE+LuREW/AEeF+qO5eiu58
LG0FsQbVZjOfFmGWRy55Wga0RnAGZH/jCn4qbroS+mlrpgXDyl+tdwtUNCMuQGiZ
y0HUPpJqG8jh0e4LDdCvGyVVLWcpqgqG/eN/SrSM7w5SDZs7yRiqrT0DkeAJ4quI
x34tG+smh4wRXUqHfcuhPyUXYUkC5M6jUPsrWoX1Gf0W8tGTzwHMs9K0Gvj0Oj/r
uXAMGoCq/Z82kCxjCCngmFs1feJUc7DYis5gzWZivz2atf0SqYnOp9Je3X3tRp83
tBALc/mAPJCCmdgP5nTFQWdu1SLjysCf66zM+DU3xnbt8KasIVfRUVk5ElUafb/5
7ss6uDTymwU0wO9rDqsV4mBYcd2jdf/ozH9bSaePj9TEmpoBNY+aMNC20nF0bin6
lbOS3z/hITZE6+pdSlxgfY66s/Dld6atXBrBD8rphQ9JwBwBN0QoKhbcRbbj8eNO
kcaJhLcMM7B58fjqJqnnsQRlITuMPfVgTv5BfFHlbmNvKC4WYaGNNWNgwAzfaKeU
7Qou5dxKwQorPHQriDuTMtkozWaW2hk02dsGE0ic7kUmBSJi3LY=
=AQZ1
-----END PGP SIGNATURE-----

--pgtmvcnqaimzwfi6--
