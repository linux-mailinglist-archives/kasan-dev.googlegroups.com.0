Return-Path: <kasan-dev+bncBAABB3OTXTBQMGQEHHLVTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id A7455AFF701
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:48:15 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b39280167fdsf477339a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115694; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ksl0maJhkWGg4EwQwCQaUW4NaHvixQy/AXFPnLRt6k0PZIpe/31pEYuzIonoTZoo2+
         O8nXspFyKV0H0HQicySbfXmKBPzlrXWyxZYBYyFCAxi99gEJhZlzo+LBstQCd7bJ7ulg
         sfpQBldlEsUS99ill2rc5cw/wsSf8tU+aL1VxsYLD3i0ocN1v+kROs6QB9iZVb87apcm
         ctskxUB8ZV8x+KgUmEZ5wDl4E8Go1hhhz/GL2273wZjPKe1h0FhmIBBTGpR3NEwNGM2D
         kRT2vd/pCHYMeKNzIq9oUBQwzakbBcJgQWjzYjDerYXastRLGQy0Jjqgm+AgO9aoF3aT
         Ijfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=89FyCYGJBpR+qJy6EKTQuurwqzurqDQ2XhE5gGsyDkE=;
        fh=aDUvWfsoLccqWnQuCXJZCYZTdiRg+niv3lYo7FLLMNM=;
        b=CevnRCz+gzOFS5rSiECTBltNvmrxIo1fJ+XtFz7tPqJpCey8zAJmfepDWM2d56ibaC
         xLuakj9vazS9fmu8uuxL4J02Q1sITT7rTh8NoeSii7IdLdzN7uhBvpwlFHK+y1pyM4+Z
         ZDuQS8Z7bxkSi+1XhsDOa3fEvj3YoMUgW2MUE0TKHCzRZUv6SQh6RoGyKAWac6uNV2Lq
         xNkLfsp+d3m0HeJjUuRwK3T9wnfhOkLmDX6XBqAP0xpz5uBAhJAgL8eXVbzU+9d7Z13I
         r8CxkTbohZwGSO2JDHmmXcFH8IcYpobk67v83PrrkdPMqM+FMVi5xwIsmLtGG5HOy1pf
         H09w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OViO6Mzk;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115694; x=1752720494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=89FyCYGJBpR+qJy6EKTQuurwqzurqDQ2XhE5gGsyDkE=;
        b=EkQZ+MUQD/fNjifQXFc1SPx9m5+8Sm6pWAx7E2rQjO33K6FbQzhP+VNdTtEE2X8GiT
         oAAknliVf0OvfDVSWX13bj7WKVjMpOY54J9bKf2eVhoL//X2vUaXoCgQXXrC+bREc5im
         mP28GoPguLRXYsBCRZLRrDDwvzyd6B0W0xbv8jke70JsUcltoRYWZ634S0HODZyXTrgY
         fh8DnqnnIEvbGOP8TyTOM8XkfxYQHHspBxDLIFuS6I7eFnsAEzHQoPkZDNMXLhULZCjf
         N2vY8lf8v/eF/O0qPMPij6BtTC1gaEq3ciPBLPqjDB9qKv4cbBEK3rYVLEzt6NoTQBjm
         lq+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115694; x=1752720494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=89FyCYGJBpR+qJy6EKTQuurwqzurqDQ2XhE5gGsyDkE=;
        b=k3Ey2M4mU2xLGyGMN8Oj8W4RnFiu7s4FaZPRAwW509bWg2FXKrotO1ssy3wJlr3JMq
         T7WLcYiQQfEzlkPYe4Fv3Dft9ldtATlnpSgX18QHxMsidYGeMI/RvBZWTvi3BhXeDmk3
         CVzzy+m6PQ/fw6bmdCxIrpA0+wQi8i5dMXUV4G477Fdxs7qa6UBadtdH2mrzuF1L7yKm
         yy9j3ShZCyPN44uCRY6o1JZ0H4wl9dvgOxZBoZIDnxIb2sktdUgbrZF2amibpiMqYIHD
         1OFA4++1ZhFw7YOwDhUr2vqI3n6pqx+PfLqeN1yXx/WR9cFMCL4BybYfbBJ1vConq67t
         4Jrg==
X-Forwarded-Encrypted: i=2; AJvYcCUE3swmLzzOn6GZ2if0Rthb+lRTq70WRivBshs/xAsnwO2Vk5vC5p9zlZQvHFnQNIzOOuUEEA==@lfdr.de
X-Gm-Message-State: AOJu0Yw6/RkNEGBjzkPfqaZ0ayUPk1psgM4TikpiT/m8dfgXtVRfwy9J
	OqZ0c/2A6x178hskXqT7LCnTqsLp4Hm43QN02cy4ijRpPO5y8kKExk9f
X-Google-Smtp-Source: AGHT+IHb/WWRZ2ffHmyOkczBU+DTaMocpqQGcZBzPyUrh/hEih0ZdAZfJUJUBhkmrtEgToalT3swTg==
X-Received: by 2002:a17:902:ccca:b0:223:653e:eb09 with SMTP id d9443c01a7336-23ddb191886mr67776555ad.7.1752115693742;
        Wed, 09 Jul 2025 19:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcii+i8BbuirCK9oGuad2Pn9VudwHy4x0/2Xg0ebaU+uA==
Received: by 2002:a17:90b:4c8f:b0:311:ba2f:7507 with SMTP id
 98e67ed59e1d1-31c3c7a7693ls615600a91.1.-pod-prod-01-us; Wed, 09 Jul 2025
 19:48:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsJv09pyjaFNpRnhJVptsyY64hWVb0ywsNqm/AsBP+O/ujtOfsNnHqCDdz+POBmXnLnRATAV6Jgfs=@googlegroups.com
X-Received: by 2002:a17:90b:1d8f:b0:301:9f62:a944 with SMTP id 98e67ed59e1d1-31c2fe0eff8mr8431856a91.33.1752115692467;
        Wed, 09 Jul 2025 19:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115692; cv=none;
        d=google.com; s=arc-20240605;
        b=K9pME4x1RPs142f+V1SDO8+4O5IkrDyEDMYAcNW+lNTvzHLvdCfjpycdY8NulzEqBO
         d7+VgIqpt2QPbufxkudQfq7+L/qwJIPJfAT9/Bzbfk+6gHzuePxBhm0ZzVy3YnQNi6J0
         HeiFbVc955ED8Pse0psgD6IXQNdU5fMyfZ4iL2jY7WV7lDGYwR+Q3Rv0yMXY1je1siXG
         YU4Xp6+bLTO0Eb08b9CMXeWolI4UI/GeQ0AG1LQutYhJEYRRIOfI5zGN+rhBa1JGnqnC
         1oX4k5LqdVo8UY9QIvHOHPfCBftsl+zNnhzvfbsy9KChEhbtyupOYS4OX7IRJ17pWoww
         UHIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qTzudb/C23xXC8XxUR2Q3efi9r0h24GZ5foCyce+LBA=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=d13Pu0E3Td1+McLKE1XynqPNrPoKZfLH92caUokeijWOLIcwAeIt3ACDjxzBu0t1uK
         cYdpd40NvxB9UCCz7ydIdVAeW78iM60PNGkcloQcIOnyv7Tba0A8b7J9SqhzaAbLPqbZ
         ddB4xGuFYlM5SfkkkFgHS47imtcLQ/WLena9sb32WmsjeLh2NAsrDfU7nRJtBIUH4zXQ
         uu44A7RyTXYTUY6zZL9zubbV2vEWxJrkLbjCS2xE0M6pruuDrYXRkltEX2hWzSBUqwuQ
         5d2dK/x35o/vtVRw0V3wuluSIODa53RdT4lsSftTmkCECU+UxFDibsfXkK+A9UKUY69R
         4UsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OViO6Mzk;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c220ed4f3si285694a91.0.2025.07.09.19.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 4E115A534A5;
	Thu, 10 Jul 2025 02:48:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C162FC4CEEF;
	Thu, 10 Jul 2025 02:48:01 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:47:58 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: alx-0049r2 - add seprintf()
Message-ID: <20250710024745.143955-1-alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OViO6Mzk;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
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

Hi,

Below is a draft of the proposal I'll submit in a few weeks to the
C Committee.


Cheers,
Alex

---
Name
	alx-0049r2 - add seprintf()

Principles
	-  Codify existing practice to address evident deficiencies.
	-  Enable secure programming

Category
	Standardize existing libc APIs

Author
	Alejandro Colomar <alx@kernel.org>

	Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>

History
	<https://www.alejandro-colomar.es/src/alx/alx/wg14/alx-0049.git/>

	r0 (2025-07-06):
	-  Initial draft.

	r1 (2025-07-06):
	-  wfix.
	-  tfix.
	-  Expand on the off-by-one bugs.
	-  Note that ignoring truncation is not valid most of the time.

	r2 (2025-07-10):
	-  tfix.
	-  Mention SEPRINTF().

Rationale
	snprintf(3) is very difficult to chain for writing parts of a
	string in separate calls, such as in a loop.

	Let's start from the obvious sprintf(3) code (sprintf(3) will
	not prevent overflow, but let's take it as a baseline from which
	programmers start thinking):

		p =3D buf;
		for (...)
			p +=3D sprintf(p, ...);

	Then, programmers will start thinking about preventing buffer
	overflows.  Programmers sometimes will naively add some buffer
	size information and use snprintf(3):

		p =3D buf;
		size =3D countof(buf);
		for (...)
			p +=3D snprintf(p, size - (p - buf), ...);

		if (p >=3D buf + size)  // or worse, (p > buf + size - 1)
			goto fail;

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here are a couple of examples:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/slub.c#L7231>
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/mempolicy.c#L3369>.)

	This has several issues, starting with the difficulty of getting
	the second argument right.  Sometimes, programmers will be too
	confused, and slap a -1 there just to be safe.

		p =3D buf;
		size =3D countof(buf);
		for (...)
			p +=3D snprintf(p, size - (p - buf) - 1, ...);

		if (p >=3D buf + size -1)
			goto fail;

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here are a couple of examples:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kfence/kfence_test.c#L1=
13>
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kmsan/kmsan_test.c#L108=
>.)

	Programmers will sometimes hold a pointer to one past the last
	element in the array.  This is a wise choice, as that pointer is
	constant throughout the lifetime of the object.  Then,
	programmers might end up with something like this:

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p +=3D snprintf(p, e - p, ...);

		if (p >=3D e)
			goto fail;

	This is certainly much cleaner.  Now a programmer might focus on
	the fact that this can overflow the pointer.  An easy approach
	would be to make sure that the function never returns more than
	the remaining size.  That is, one could implement something like
	this scnprintf() --name chosen to match the Linux kernel API of
	the same name--.  For the sake of simplicity, let's ignore
	multiple evaluation of arguments.

		#define scnprintf(s, size, ...)                 \
		({                                              \
			int len_;                               \
			len_ =3D snprintf(s, size, __VA_ARGS__);  \
			if (len_ =3D=3D -1)                         \
				len_ =3D 0;                       \
			if (len_ >=3D size)                       \
				len_ =3D size - 1;                \
		                                                \
			len_;                                   \
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p +=3D scnprintf(p, e - p, ...);

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here's an example:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kfence/kfence_test.c#L1=
31>.)

	Now the programmer got rid of pointer overflow.  However, they
	now have silent truncation that cannot be detected.  In some
	cases this may seem good enough.  However, often it's not.  And
	anyway, some code remains using snprintf(3) to be able to detect
	truncation.

	Moreover, this kind of code ignores the fact that vsnprintf(3)
	can fail internally, in which case there's not even a truncated
	string.  In the kernel, they're fine, because their internal
	vsnprintf() doesn't seem to ever fail, so they can always rely
	on the truncated string.  This is not reliable in projects that
	rely on the libc vsnprintf(3).

	For the code that needs to detect truncation, a programmer might
	choose a different path.  It would keep using snprintf(3), but
	would use a temporary length variable instead of the pointer.

		p =3D buf;
		e =3D buf + countof(buf);
		for (...) {
			len =3D snprintf(p, e - p, ...);
			if (len =3D=3D -1)
				goto fail;
			if (len >=3D e - p)
				goto fail;
			p +=3D len;
		}

	This is naturally error-prone.  A colleague of mine --which is an
	excellent programmer, to be clear--, had a bug even after
	knowing about it and having tried to fix it.  That shows how
	hard it is to write this correctly:
	<https://github.com/nginx/unit/pull/734#discussion_r1043963527>

	In a similar fashion, the strlcpy(3) manual page from OpenBSD
	documents a similar issue when chaining calls to strlcpy(3)
	--which was designed with semantics equivalent to snprintf(3),
	except for not formatting the string--:

	|	     char *dir, *file, pname[MAXPATHLEN];
	|	     size_t n;
	|
	|	     ...
	|
	|	     n =3D strlcpy(pname, dir, sizeof(pname));
	|	     if (n >=3D sizeof(pname))
	|		     goto toolong;
	|	     if (strlcpy(pname + n, file, sizeof(pname) - n) >=3D sizeof(pname) =
- n)
	|		     goto toolong;
	|
	|       However, one may question the validity of such optimiza=E2=80=90
	|       tions, as they defeat the whole purpose of strlcpy() and
	|       strlcat().  As a matter of fact, the  first  version  of
	|       this manual page got it wrong.

	Finally, a programmer might realize that while this is error-
	prone, this is indeed the right thing to do.  There's no way to
	avoid it.  One could then think of encapsulating this into an
	API that at least would make it easy to write.  Then, one might
	wonder what the right parameters are for such an API.  The only
	immutable thing in the loop is 'e'.  And apart from that, one
	needs to know where to write, which is 'p'.  Let's start with
	those, and try to keep all the other information (size, len)
	without escaping the API.  Again, let's ignore multiple-
	evaluation issues in this macro for the sake of simplicity.

		#define foo(p, e, ...)                                \
		({                                                    \
			int  len_ =3D snprintf(p, e - p, __VA_ARGS__);  \
			if (len_ =3D=3D -1)                               \
				p =3D NULL;                             \
			else if (len_ >=3D e - p)                       \
				p =3D NULL;                             \
			else                                          \
				p +=3D len_;                            \
			p;
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...) {
			p =3D foo(p, e, ...);
			if (p =3D=3D NULL)
				goto fail;
		}

	We've advanced a lot.  We got rid of the buffer overflow; we
	also got rid of the error-prone code at call site.  However, one
	might think that checking for truncation after every call is
	cumbersome.  Indeed, it is possible to slightly tweak the
	internals of foo() to propagate errors from previous calls.

		#define seprintf(p, e, ...)                           \
		({                                                    \
			if (p !=3D NULL) {                              \
				int  len_;                            \
		                                                      \
				len_ =3D snprintf(p, e - p, __VA_ARGS__); \
				if (len_ =3D=3D -1)                       \
					p =3D NULL;                     \
				else if (len_ >=3D e - p)               \
					p =3D NULL;                     \
				else                                  \
					p +=3D len_;                    \
			}                                             \
			p;                                            \
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p =3D seprintf(p, e, ...);

		if (p =3D=3D NULL)
			goto fail;

	By propagating an input null pointer directly to the output of
	the API, which I've called seprintf() --the 'e' refers to the
	'end' pointer, which is the key in this API--, we've allowed
	ignoring null pointers until after the very last call.  If we
	compare our resulting code to the sprintf(3)-based baseline, we
	got --perhaps unsurprisingly-- something quite close to it:

		p =3D buf;
		for (...)
			p +=3D sprintf(p, ...);

	vs

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p =3D seprintf(p, e, ...);

		if (p =3D=3D NULL)
			goto fail;

	And the seprintf() version is safe against both truncation and
	buffer overflow.

	For the case where there is only one call to this function (so
	not chained), and the buffer is an array, an even more ergonomic
	wrapper can be written, and it is recommended that projects
	define this macro themselves:

		#define SEPRINTF(a, fmt, ...)  \
			seprintf(a, a + countof(a), fmt, __VA_ARGS__)

	This adds some safety guarantees that $2 is calculated correctly
	when it can be automated.  Correct use would look like

		if (SEPRINTF(buf, "foo") =3D=3D NULL)
			goto fail;

	Some important details of the seprintf() API are:

	-  When 'p' is NULL, the API must preserve errno.  This is
	   important to be able to determine the cause of the error
	   after all the chained calls, even when the error occurred in
	   some call in the middle of the chain.

	-  When truncation occurs, a distinct errno value must be used,
	   to signal the programmer that at least the string is reliable
	   to be used as a null-terminated string.  The error code
	   chosen is E2BIG, for compatibility with strscpy(), a Linux
	   kernel internal API with which this API shares many features
	   in common.

	-  When a hard error (an internal snprintf(3) error) occurs, an
	   error code different than E2BIG must be used.  It is
	   important to set errno, because if an implementation would
	   chose to return NULL without setting errno, an old value of
	   E2BIG could lead the programmer to believe the string was
	   successfully written (and truncated), and read it with
	   nefast consequences.

Prior art
	This API is implemented in the shadow-utils project.

	Plan9 designed something quite close, which they call
	seprint(2).  The parameters are the same --the right choice--,
	but they got the semantics for corner cases wrong.  Ironically,
	the existing Plan9 code I've seen seems to expect the semantics
	that I chose, regardless of the actual semantics of the Plan9
	API.  This is --I suspect--, because my semantics are actually
	the intuitive semantics that one would naively guess of an API
	with these parameters and return value.

	I've implemented this API for the Linux kernel, and found and
	fixed an amazing amount of bugs and other questionable code in
	just the first handful of files that I inspected.
	<https://lore.kernel.org/linux-hardening/cover.1751747518.git.alx@kernel.o=
rg/T/#t>
	<https://lore.kernel.org/linux-hardening/cover.1751823326.git.alx@kernel.o=
rg/T/#t>

Future directions
	The 'e =3D buf + _Countof(buf)' construct is something I've found
	to be quite common.  It would be interesting to have an
	_Endof operator that would return a pointer to one past the last
	element of an array.  It would require an array operand, just
	like _Countof.  If an _Endof operator is deemed too cumbersome
	for implementation, an endof() standard macro that expands to
	the obvious implementation with _Countof could be okay.

	This operator (or operator-like macro) would prevent off-by-one
	bugs when calculating the end sentinel value, such as those
	shown above (with links to Linux kernel real bugs).

Proposed wording
	Based on N3550.

    7.24.6  Input/output <stdio.h> :: Formatted input/output functions
	## New section after 7.24.6.6 ("The snprintf function"):

	+7.24.6.6+1  The <b>seprintf</b> function
	+
	+Synopsis
	+1	#include <stdio.h>
	+	char *seprintf(char *restrict p, const char end[0], const char *restrict=
 format, ...);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to <b>fprintf</b>,
	+	except that the output is written into an array
	+	(specified by argument <tt>p</tt>)
	+	rather than a stream.
	+	If <tt>p</tt> is a null pointer,
	+	nothing is written,
	+	and the function returns a null pointer.
	+	Otherwise,
	+	<tt>end</tt> shall compare greater than <tt>p</tt>;
	+	the function writes at most
	+	<tt>end - p - 1</tt> non-null characters,
	+	the remaining output characters are discarded,
	+	and a null character is written
	+	at the end of the characters
	+	actually written to the array.
	+	If copying takes place between objects that overlap,
	+	the behavior is undefined.
	+
	+Returns
	+3	The <b>$0</b> function returns
	+	a pointer to the terminating null character
	+	if the output was written
	+	without discarding any characters.
	+
	+4
	+	If <tt>p</tt> is a null pointer,
	+	a null pointer is returned,
	+	and <b>errno</b> is not modified.
	+
	+5
	+	If any characters are discarded,
	+	a null pointer is returned,
	+	and the value of the macro <b>E2BIG</b>
	+	is stored in <b>errno</b>.
	+
	+6
	+	If an error occurred,
	+	a null pointer is returned,
	+	and an implementation-defined non-zero value
	+	is stored in <b>errno</b>.

	## New section after 7.24.6.13 ("The vsnprintf function"):

	+7.24.6.13+1  The <b>vseprintf</b> function
	+
	+Synopsis
	+1	#include <stdio.h>
	+	char *vseprintf(char *restrict p, const char end[0], const char *restric=
t format, va_list arg);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>seprintf</b>,
	+	with the varying argument list replaced by <tt>arg</tt>.
	+
	+3
	+	The <tt>va_list</tt> argument to this function
	+	shall have been initialized by the <b>va_start</b> macro
	+	(and possibly subsequent <b>va_arg</b> invocations).
	+	This function does not invoke the <b>va_end</b> macro.343)

    7.33.2  Formatted wide character input/output functions
	## New section after 7.33.2.4 ("The swprintf function"):

	+7.33.2.4+1  The <b>sewprintf</b> function
	+
	+Synopsis
	+1	#include <wchar.h>
	+	wchar_t *sewprintf(wchar_t *restrict p, const wchar_t end[0], const wcha=
r_t *restrict format, ...);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>seprintf</b>,
	+	except that it handles wide strings.

	## New section after 7.33.2.8 ("The vswprintf function"):

	+7.33.2.8+1  The <b>vsewprintf</b> function
	+
	+Synopsis
	+1	#include <wchar.h>
	+	wchar_t *vsewprintf(wchar_t *restrict p, const wchar_t end[0], const wch=
ar_t *restrict format, va_list arg);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>sewprintf</b>,
	+	with the varying argument list replaced by <tt>arg</tt>.
	+
	+3
	+	The <tt>va_list</tt> argument to this function
	+	shall have been initialized by the <b>va_start</b> macro
	+	(and possibly subsequent <b>va_arg</b> invocations).
	+	This function does not invoke the <b>va_end</b> macro.407)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250710024745.143955-1-alx%40kernel.org.
