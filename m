Return-Path: <kasan-dev+bncBCO3PDUQQMDRBVE2YXBQMGQEAG3RWWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4590FB022EB
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 19:43:50 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45320bfc18dsf13679335e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 10:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752255830; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qq6R3ZAR5A1i02frZk42WktkiLwErDWDTLY81UMelyJw+3zy2iNlvhbkEf8WQYeyYw
         jdSpBRHfWuCeBGRAlgujFlUFVH4LEwd63v23+ImfBCgf5ec9OHw1SEAKoz3H21140P3b
         oeOvSg7iWoh5wKx4tNb7dz/VKC909lWlZhmcC/THvmAKawffv35QdfwAo2k2p3tsC4/c
         sW/T1JMq7vt7sdF9ZV5IAfWkhtni0hTfM0tS0q/MFtXUMvUf1Ygg/0p5PCrmBrgv9IWY
         ezo9EE6VlO48SCI4iUiwjiWbdy53arYCIQR3dfuHaABVHXm8mVRSwW1dxCjqCMtBgUes
         2LeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=wNzxqkubk2W7P2RLacazyLGtXKqd97ugIAQuyhCiDsg=;
        fh=LaZPQtUXLMelVkGRv+oZlbkTgBsALYQQUGh1Hjw6LOg=;
        b=BS1kOyO/wyO7B1eCU4wWTZrudn5O0Ux9IXj5wYFewwa/9y9Ids9/hsofxQ1oV/178Q
         ns71s3LCCIZKIV6gEEqkxEG/mtEAUn65mJiCDjHDg1+3WbpIsid8DXVst3dP33H8kVF9
         +7vlnysOzPxtjRxy1vYjvWBYnOhxeG4+J2ynOM31Dm8f0bUyRBuimmI06LW10S4Lr+1+
         EmVq5VvlLaDqVQov5tqeeA1PzNJlCXo8HQwJ+JByvBYVcnBKFKQpy+ROYQcV1s9lLRKf
         BvWO5f1TaRlZekuSopMN4wyLanVkAoUF/myNrn6vSrGE/kN1jpRHG2qI2ldZdF1Elvi9
         kWgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m4wDQZKE;
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752255830; x=1752860630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wNzxqkubk2W7P2RLacazyLGtXKqd97ugIAQuyhCiDsg=;
        b=QoYqYH5OmZWf4B3DhWpr6ioA7OjkXsosDFChj7h2wLxYHX8cmdRgLvqyBUpngPk4X5
         z/X5HnegTMRMkKjq+hoE7HgxNqzPf9iyNAq2aZZLeuD2Ig1EzD8rM7GB0KawRPF4o+E6
         D1oQEdAKvVPzbL7ymV7eB3hzCxSYCYBaQTEuPmhVnc17O69rwvf85GtlSv2H8Zycp3w7
         C+WNG/dXGtgzW+iuhfsCj0u52kEif03eqIOOsQ3Ak1YPTGuzMXMSQ5cLl8xSW7B0Cchg
         L5PUTTE1TNEFZJ5zxMPuDzHUQy1L5RaGJeugPhm2vkD43nMHUHH/4B2cLXGWin5p/ChO
         udlw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752255830; x=1752860630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wNzxqkubk2W7P2RLacazyLGtXKqd97ugIAQuyhCiDsg=;
        b=LiGMI2ZCztvAz8Vypcn+JveZbedb5k+/jIvyI7kAXH15TqAzrb6d0FIH8/ZFgPfwnZ
         3yaxO7cndfLtt/sucrhY1sm/4kwBxWF3TZ3X8zxq+Xk8fbYzDY8oLR6R3ETB6XB9oK+q
         A7WGRTIlN0VoIAk53r9w2qHo1fyPlnk8R6S106QgnHWBBekSgowDHmmtq8tgGsK5OLtC
         3OWxSmViniLP5eIUEUYaI3Y1ELKZ1Js4hT/wlGBFp1ZZClEgOEFYhjwpWDnlTS2rmq3S
         Rhyy3K/0gfAPtIhM4vFeGR7U4LuJKaVNks6eXVrzcrG8ByRyAe303KnUb3fg2OjG7vJa
         Ol0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752255830; x=1752860630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wNzxqkubk2W7P2RLacazyLGtXKqd97ugIAQuyhCiDsg=;
        b=HmarHOzd5ooUCA51w3aQX0c0SZ3KwyorUXhXWfleABziTNnCwzkBgX1+hnnSwuuN0E
         8CkxZPl2xg8pWgS0zW2OZckcA2z9oCwuStt+3pgWDyVuqzkN63VnOHK8v/JsC4b6gkie
         kVAXosSS3Cl18mh+LrdCfaB+QdJegQCRrQJtR/nVzJqoMwyBAtasiFN+867i96Pk72Qc
         FbG5IVvcplnMse/8uumobHjpnQ9glklfwZ+ACuqZzvgVygorX90eE4ohu/PTiOTAxs8h
         7CGvALwmUOJzna6IU0of0vlzKYQQicHLdTQL4V5DUXOok6v/PAkPH1TyTU0z3rBXhvOL
         TzkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz4MB1C29jhyNY0014JDn4VTSrvxgTfbtk+r1tUv5rJHKDwZfc7bNhVeBZyHGfYPanPMkUag==@lfdr.de
X-Gm-Message-State: AOJu0Yz+/dVCHiCnGRSRoh52snKitQwKHtlN2hi3FLGAcg6S/hrko/LZ
	swq5mAonMoenBjGGia/YLqPpBUM5i/Ry4ZeuD8F95Mid2Sn6dzjISZdJ
X-Google-Smtp-Source: AGHT+IGvVWIgKNPWeYEd1t1T9dL/piPy78Xk7CR/FWTLD5uEwDNsdQAZSg+r9PRwA1YAykZb6MTwgQ==
X-Received: by 2002:a05:600c:a10d:b0:453:8e3d:26ef with SMTP id 5b1f17b1804b1-454db88f677mr71246295e9.6.1752255829409;
        Fri, 11 Jul 2025 10:43:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeS+LIibOrEva5PFqBeucxb/6mHvEdfwQxzg7Sjygy7Zw==
Received: by 2002:a05:600c:1546:b0:43c:f001:2ff1 with SMTP id
 5b1f17b1804b1-454db4557bals8346925e9.0.-pod-prod-00-eu; Fri, 11 Jul 2025
 10:43:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdgJ92+/Uqml4syoDEWuY5DGjYx1RADTHM9364bXVMkhPBvo7c72TnmP4OFT/hcIKns9O9qcFChnI=@googlegroups.com
X-Received: by 2002:a05:600c:1e88:b0:453:69dc:2621 with SMTP id 5b1f17b1804b1-454e2b4b1a8mr45953165e9.12.1752255826155;
        Fri, 11 Jul 2025 10:43:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752255826; cv=none;
        d=google.com; s=arc-20240605;
        b=c+1/v+pLtWjiq87l2jg/nUOxwwar+0GvfohzxJQZQMgTL1tu2kGLbrK/9xSVGk8K6U
         0BduWAJOnnnnxI3Ad19vJi8roXe6DEM8W/8Y1FHl3AnjKqtM1LgKP4FeFjae7MLS+N8s
         FBGtPT+RaBG4iEANFFxh3XPyOWPXHlA7/2XD1DLyhBuvsXmuvTBwSqHEaGP90jzTypzy
         KaXber0r8x4lVbwzpt9m8gYds/yRjkLB5OGdncT5mwnqO7iJ5ebUTlzljd+tN0geu974
         elpJQuYjx5B88n4XY05MQWQpDih16EIDpdyXFnadMO2um+xVwD08lHRbkPfP30C23ygx
         ZZpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VknUmgzMCiBefIq6vhslDBLHtoemuumEdTr+qyL4BSs=;
        fh=0u7Ze7asMjlXIquz2dTStZr3I4n3N03Y2LJkhhJ6UU4=;
        b=UYAEpCxSsF8gNTMXFB3ngwTAz+GaahNrL6EdSVQZ2wSYwY6FImGtCWKwgWyNk5DGUo
         g47FMXOka3NShnam5zy3f7fMq7PrcEVkuwFzqyU3jA9I3VZRoJsZik8dcbyp+SoSCaS6
         3AQ/WfBhOlLft0fsFPTKl9Fbjwyu4pmzc3fuIEJVPhZ9g1dPLfygq6FgA8+g0hasrvg4
         tzOFs2GXEPffLHTuBn1L/ZGFSschSdUZjv1iTWgo4ljVPiXRftTOcxpvGVP1E/6v779c
         xVYHVa5BlBQY7axl2sfKrjvfn6zQu5gX0higCIWv5T8yq4AigOoXak4grrxS9U8B0+6x
         xeJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m4wDQZKE;
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454d3672b87si2673965e9.0.2025.07.11.10.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 10:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3a4e742dc97so2204117f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 10:43:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWk8C1/U5ZOdfY3EhtKg2JY8xdO2Lbci54uYW4NIFZCIIw5/C9Yrey5AvHAO8eRl9WBbM+maUuRixg=@googlegroups.com
X-Gm-Gg: ASbGncsgN8J2ydKNBppr6suRbnkIDppGS6qbrIgTBTT+iwODZO9nVukpLX9FVaGlyJZ
	ljej7sFUUGqfvg6VKC2zfAL6/gJiAKZyy1McqdDo1NcmijWHlfRdqk4hsfF/h9cAfFN4DNWfdLR
	TtpqPqw9vVUFGbA5R8GsCs+5kBKGozlP65rc1odP148h8JxGg0lAYKdlg+qo3OslM/dhS74h3Ov
	xVZmGMoVT2xvbLEi946gr+ikAtXmPuB6bTWICwRcWh3SrWy/HT0M7Vd9URppxV9vByAaGCkqCYp
	EEGhn4CF733TQfZ64QPxhN+By1jCkNE+uBA7LJigV1QtUFQCwMgZGjPSGLsEmy27HmXof4wwCpd
	TURkMTQt5kXR8c9uIqn20yP5Uq7c2aULl44qcsHo6zezkX2sJlYb8LQ==
X-Received: by 2002:a05:6000:2f86:b0:3a0:b565:a2cb with SMTP id ffacd0b85a97d-3b5f1c67becmr3586044f8f.1.1752255825300;
        Fri, 11 Jul 2025 10:43:45 -0700 (PDT)
Received: from pumpkin (host-92-21-58-28.as13285.net. [92.21.58.28])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b5e8e1e1a5sm4954576f8f.74.2025.07.11.10.43.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 10:43:45 -0700 (PDT)
Date: Fri, 11 Jul 2025 18:43:43 +0100
From: David Laight <david.laight.linux@gmail.com>
To: Alejandro Colomar <alx@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org,
 linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, Christopher
 Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>,
 linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, Alexander
 Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph
 Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil
 Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, Harry
 Yoo <harry.yoo@oracle.com>, Andrew Clayton <andrew@digital-domain.net>,
 Rasmus Villemoes <linux@rasmusvillemoes.dk>, Michal Hocko
 <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker
 <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <20250711184343.5eabd457@pumpkin>
In-Reply-To: <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
References: <cover.1751823326.git.alx@kernel.org>
	<cover.1752182685.git.alx@kernel.org>
	<04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	<CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
	<krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.38; arm-unknown-linux-gnueabihf)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight.linux@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m4wDQZKE;       spf=pass
 (google.com: domain of david.laight.linux@gmail.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, 11 Jul 2025 01:23:49 +0200
Alejandro Colomar <alx@kernel.org> wrote:

> Hi Linus,
> 
> [I'll reply to both of your emails at once]
> 
> On Thu, Jul 10, 2025 at 02:58:24PM -0700, Linus Torvalds wrote:
> > You took my suggestion, and then you messed it up.
> > 
> > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > argument.  
> 
> An array has no issue being evaluated twice (unless it's a VLA).  On the
> other hand, I agree it's better to not do that in the first place.
> My bad for forgetting about it.  Sorry.

Or a function that returns an array...

	David

> 
> On Thu, Jul 10, 2025 at 03:08:29PM -0700, Linus Torvalds wrote:
> > If you want to return an error on truncation, do it right.  Not by
> > returning NULL, but by actually returning an error.  
> 
> Okay.
> 
> > For example, in the kernel, we finally fixed 'strcpy()'. After about a
> > million different versions of 'copy a string' where every single
> > version was complete garbage, we ended up with 'strscpy()'. Yeah, the
> > name isn't lovely, but the *use* of it is:  
> 
> I have implemented the same thing in shadow, called strtcpy() (T for
> truncation).  (With the difference that we read the string twice, since
> we don't care about threads.)
> 
> I also plan to propose standardization of that one in ISO C.
> 
> >  - it returns the length of the result for people who want it - which
> > is by far the most common thing people want  
> 
> Agree.
> 
> >  - it returns an actual honest-to-goodness error code if something
> > overflowed, instead of the absoilutely horrible "source length" of the
> > string that strlcpy() does and which is fundamentally broken (because
> > it requires that you walk *past* the end of the source,
> > Christ-on-a-stick what a broken interface)  
> 
> Agree.
> 
> >  - it can take an array as an argument (without the need for another
> > name - see my earlier argument about not making up new names by just
> > having generics)  
> 
> We can't make the same thing with sprintf() variants because they're
> variadic, so you can't count the number of arguments.  And since the
> 'end' argument is of the same type as the formatted string, we can't
> do it with _Generic reliably either.
> 
> > Now, it has nasty naming (exactly the kind of 'add random character'
> > naming that I was arguing against), and that comes from so many
> > different broken versions until we hit on something that works.
> > 
> > strncpy is horrible garbage. strlcpy is even worse. strscpy actually
> > works and so far hasn't caused issues (there's a 'pad' version for the
> > very rare situation where you want 'strncpy-like' padding, but it
> > still guarantees NUL-termination, and still has a good return value).  
> 
> Agree.
> 
> > Let's agree to *not* make horrible garbage when making up new versions
> > of sprintf.  
> 
> Agree.  I indeed introduced the mistake accidentally in v4, after you
> complained of having too many functions, as I was introducing not one
> but two APIs: seprintf() and stprintf(), where seprintf() is what now
> we're calling sprintf_end(), and stprintf() we could call it
> sprintf_trunc().  So I did the mistake by trying to reduce the number of
> functions to just one, which is wrong.
> 
> So, maybe I should go back to those functions, and just give them good
> names.
> 
> What do you think of the following?
> 
> 	#define sprintf_array(a, ...)  sprintf_trunc(a, ARRAY_SIZE(a), __VA_ARGS__)
> 	#define vsprintf_array(a, ap)  vsprintf_trunc(a, ARRAY_SIZE(a), ap)
> 
> 	char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
> 	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
> 	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
> 	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);
> 
> 	char *sprintf_end(char *p, const char end[0], const char *fmt, ...)
> 	{
> 		va_list args;
> 
> 		va_start(args, fmt);
> 		p = vseprintf(p, end, fmt, args);
> 		va_end(args);
> 
> 		return p;
> 	}
> 
> 	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
> 	{
> 		int len;
> 
> 		if (unlikely(p == NULL))
> 			return NULL;
> 
> 		len = vsprintf_trunc(p, end - p, fmt, args);
> 		if (unlikely(len < 0))
> 			return NULL;
> 
> 		return p + len;
> 	}
> 
> 	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
> 	{
> 		va_list args;
> 		int len;
> 
> 		va_start(args, fmt);
> 		len = vstprintf(buf, size, fmt, args);
> 		va_end(args);
> 
> 		return len;
> 	}
> 
> 	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
> 	{
> 		int len;
> 
> 		if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
> 			return -EOVERFLOW;
> 
> 		len = vsnprintf(buf, size, fmt, args);
> 		if (unlikely(len >= size))
> 			return -E2BIG;
> 
> 		return len;
> 	}
> 
> sprintf_trunc() is like strscpy(), but with a formatted string.  It
> could replace uses of s[c]nprintf() where there's a single call (no
> chained calls).
> 
> sprintf_array() is like the 2-argument version of strscpy().  It could
> replace s[c]nprintf() calls where there's no chained calls, where the
> input is an array.
> 
> sprintf_end() would replace the chained calls.
> 
> Does this sound good to you?
> 
> 
> Cheers,
> Alex
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250711184343.5eabd457%40pumpkin.
