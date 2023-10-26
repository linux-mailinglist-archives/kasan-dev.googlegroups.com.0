Return-Path: <kasan-dev+bncBDW2JDUY5AORBU7I5OUQMGQEDU5B5TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 683D27D8C27
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 01:20:53 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6ce2b33816esf1830602a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 16:20:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698362452; cv=pass;
        d=google.com; s=arc-20160816;
        b=ND6a+LY65lnaS0nNjIk3sucxB0AJeINzc/ZeicZ5FLx9fI5R8k5sk26TqWFODuvvWs
         5qin32GvXQT44mHDs7Rwl2aVGnHI+AQyi7IcnfWAStRh/9hlZbnQOHEzjyI7UqPHhZ5O
         GgWfFob1YLKvjXb1j/mVic7Qq3ncupN/ezX4cTHwP6dAgfrLBaIMAUw3sbKOqaFw2uU+
         0n77HUcpgmgifzMm5Ay6rxE7tF/R6FJUjo/eKX3JkQUuuD5JuZ9xbdb262A5CgZONxpo
         PEMqIBLIce/Ryog3B92WiFxlp1taPUVkAJNTjHJVQcTPaCgYhu9/naGF8w0Wv9FPuh4t
         93Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wPJq6Eksui98ykWRdV+9x5CB6xs5q4q9o3ZoilNegg4=;
        fh=atFGOu85uyxoIXRWZ3/h2I6Z7KaAbtJxXXzcbpFCNqU=;
        b=ap7RilA/w5y/dgQvNhCmv1EglbyZ2MI/jfkdVw0jaLt4W9JQUmFPJs3fJd15madqkJ
         jU2z+QdzU/aUbrROPW5315K2ifElXHZIdLjHp6bB4QaKekeJ1bw2zydwwWASvBKwov0J
         Bn1M2l685V5KTfHG/om9f83ZAGQucvcb49sZMkPDsv5g2ijSJFfa+27hbn+e64WerLpM
         xk2lsWYK05hNtA48gvNO1EekfF/xtnIwamclmFSbfpUxaHBUmX8UKAFZvFYmCDH+Y6hV
         sh5zd3v/nqmcAspFtSAlTr+PB3xNsjtvKQhx9cXtmeRy3v86R1XRtsJHvpcjHZNFBp1z
         9AAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XWEw+Y+K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698362452; x=1698967252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wPJq6Eksui98ykWRdV+9x5CB6xs5q4q9o3ZoilNegg4=;
        b=EfDW4mdf2TWTX8E74HSf4/rHCFj4FN653XT84PhLVEpHBI9AGconRHJEevYudjmL68
         SjElyQFd4KVGFi/8eSDgEL2HkejgQXJTnn2uvgSPYSe92Ubx1efhA7AP+stq5A2HINkn
         PjjPw9k1H3IRcDq4pbE0hxwyH/MaEHZ5Wc/32VCxSYkvI8gfDqXArUmEfuunOgp7Ssdw
         B85FgJRrkqxW99V0GXoOQNle/SoNC9IrwS3oe9/0y7bSH+eDzq0wPF8dxm9zTFrhNpkb
         JgdN0IDATC2P+MJtRrFszidTYaAJpWWm8Ni3Pa00LbenvaXPVD7dXXxupLc9+BGkj+CI
         XUaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698362452; x=1698967252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wPJq6Eksui98ykWRdV+9x5CB6xs5q4q9o3ZoilNegg4=;
        b=TmEbroBr72jdddergIugtyNexeI1q03xKMNXKso09ccbQlrNp7hJdaRPJI+uebiVkU
         xC2eauNzcXT7qXrNL7Dg2vWNkAVYSlwM0gZzvB6rryDwcPe28jgQ692ns1Lkiym1dm/b
         B1KAvvaT6sKgGwrdeVOnqYQT9Fb6IsuoMys7Ayyo+NAxaz2ay0fgrnBaxhKaHIT3yBUa
         x+IHWMPSrreFcnN//5rTOJXxslMonZSH76etEzDIY0gzZ19YezAMl/OmSQR9kAozLols
         UEHSZPRhktSSJbjuOB2IARs+gzcwxmLJWBe9tqFbnmH+4/TxIiPCUxInpHjEkG2vtUR/
         b5KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698362452; x=1698967252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wPJq6Eksui98ykWRdV+9x5CB6xs5q4q9o3ZoilNegg4=;
        b=cEY29rTlX5WUxkGR57uDyWpp+Z22XCia30FLC4o5BbgOqku/gmwmwYLGkzMIlQKROE
         GGRH+p+FiMThlIVKQTaGQgb8aARGIrQNOR2oHpNxikxp59UVBuo1DESSvE+Ffg4v33IP
         oh7J4G4MsGQl+HxgJ/I5ILUAxaISsosmxuR9t3DhLXN9QR8jwlV+A6Z4QfJxQmZOJgzI
         CgYCiyeksJ9TgUdWUXi1nOhGjnb+jRQgtlAF8v1acXMScCVNKX+KCXgxDjV9ethIkF1H
         jz+5+dKAi91+6EpcUGqMWr5dmx90MLfHCxAT3/UvDkZ7Pbb6mSC1jm4/B8wEc8YwONcf
         HLZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxNbVdTzfyXrvsOhhhbm10aYowx34E3WAjpoYXR7piuAyCp7srM
	/T6urQjiP00/6aLbyAoPEaM=
X-Google-Smtp-Source: AGHT+IFMg5SX1s5palkugHYtxPjOsBPu9EyWl+1auyvFQhQj/tXUmmGVGmlpwd6+qlAfr/cV/OCjKw==
X-Received: by 2002:a05:6870:d189:b0:1e9:8780:a0e with SMTP id a9-20020a056870d18900b001e987800a0emr903739oac.28.1698362452016;
        Thu, 26 Oct 2023 16:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:592:b0:1dd:47e:9bc1 with SMTP id
 m18-20020a056870059200b001dd047e9bc1ls819266oap.2.-pod-prod-09-us; Thu, 26
 Oct 2023 16:20:51 -0700 (PDT)
X-Received: by 2002:a05:6358:7e47:b0:168:efa4:3c66 with SMTP id p7-20020a0563587e4700b00168efa43c66mr1389303rwm.24.1698362451471;
        Thu, 26 Oct 2023 16:20:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698362451; cv=none;
        d=google.com; s=arc-20160816;
        b=wbH/fg2LE2/rgfk+Mz67ypkx5BDMqcs12KAZesBQfzJoWpwCuqtNCNfLTAkz78KF2J
         KKJeDjEWP89kObDAWQgltAO8Ocl2+lgDItmNp2kZB1NBZ/Puxe5iYkiR5PY4jZKk7kSy
         0DF/HjMHrKGPD1LU0BzewJVr3Bic3TmLnKWQrIvg5nwv4lJJnUuXIqB/OWMvor/6i20i
         gcW9MMwufY63YVcmXvev3Fc4PjZsaI1cx8y67nZnNOWLwR5n2ifsf8bZGFcuGvM9IQ4J
         5qCSaY12gRG7JRlOQtziQJ6vozkXXihdDemlvWla3Bpynor0YolYySRoN7mM/NUssA+t
         bRCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0g3EqhxCq65C/tYb/O2boXzXlPPUEvW+TMQUtT+idPE=;
        fh=atFGOu85uyxoIXRWZ3/h2I6Z7KaAbtJxXXzcbpFCNqU=;
        b=u+npX9vBifbBuWs6dH+Ys8icpcW9KZNfI/pEzEbZ1hZHtZJxW4Tnc3GIXOu6Ooi8MT
         aIlSFySANbisXFW/wUOReaofLekl79/EE8PYS6TjPWUxUGmy4z28RSUj9Ab3M9yYi3nI
         sS1WSkNPABwh5hdtvHcn3rCwnw5HoqxWAfTOJQIxmN+UOWYNhMDFi7n25FLSVdS1dmZE
         tY4N+ZxK1m+lPvibb/OL4dyoDD4TAgf4Ni4BHRD1OFpL7VqQHQFVF/ahjYLcZtCJa0eB
         dSqdtOBy4vNDL6Cx4/lMZXkarYPf6z9cxN4OsOjZfJ9ab+DepZwCLBZzy278Z0QxqSgL
         MphA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XWEw+Y+K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id u23-20020a056a00099700b00690d911f63fsi17474pfg.4.2023.10.26.16.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Oct 2023 16:20:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-564af0ac494so1271100a12.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Oct 2023 16:20:51 -0700 (PDT)
X-Received: by 2002:a17:90b:1a8d:b0:274:616e:3fc4 with SMTP id
 ng13-20020a17090b1a8d00b00274616e3fc4mr1001903pjb.34.1698362451039; Thu, 26
 Oct 2023 16:20:51 -0700 (PDT)
MIME-Version: 1.0
References: <20231026223340.333159-1-andrey.konovalov@linux.dev> <20231026160715.ea74f79dea9960b8ff46d077@linux-foundation.org>
In-Reply-To: <20231026160715.ea74f79dea9960b8ff46d077@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 27 Oct 2023 01:20:39 +0200
Message-ID: <CA+fCnZcy5cCHTtXmVmUngL_PPjLLX-O2uDYtSaM-=G_kO=GHMw@mail.gmail.com>
Subject: Re: [PATCH] fix for "lib/stackdepot: allow users to evict stack traces"
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Oscar Salvador <osalvador@suse.de>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XWEw+Y+K;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Oct 27, 2023 at 1:07=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Fri, 27 Oct 2023 00:33:40 +0200 andrey.konovalov@linux.dev wrote:
>
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Commit "lib/stackdepot: allow users to evict stack traces" adds another
> > user for depot_fetch_stack, which holds a write lock. Thus, we need to
> > update the lockdep annotation.
> >
>
> We're at -rc7, which is rather late to be merging material such as this
> patchset.  Please resend it all after -rc1 and include this fixup,
> thanks.

Ack.

I might send a few more additions to the series for review before
then, but then resend everything together after rc1.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcy5cCHTtXmVmUngL_PPjLLX-O2uDYtSaM-%3DG_kO%3DGHMw%40mail.=
gmail.com.
