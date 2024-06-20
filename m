Return-Path: <kasan-dev+bncBCCMH5WKTMGRBR4H2GZQMGQETG6L6KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DA0F910929
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 16:59:21 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-7eb7c3b8cf8sf111112639f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 07:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718895560; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCDtU1IZgVE0QWFQ+05SpRkEVlcOzwqlY5p7MItVgZrSK7vpnf6w/RvNpObPmupW1u
         t1QHlHyCLyG0kCCtSzfhvC723C44mh0aCMt0eSepFzm0zkEfVk6YrNMIFf+mC5UeO6om
         f3WNccaAiyvTjOz0lG2QO1ccGDjZzrv/5G3IVC0nd+mqi/JvBSkEe496YT7JrJu9bRev
         pOwT27e79qrj7Kcq8G7tmFi3UfQj1oxDQ/tJmZftJNHZ2AdmeKckmNTr069p/w34OqTF
         WJa8b6GBOfqPD5yYtgx4yrVyZhmFw/Vj8TtRJs1PcXYt+zSxTuHfd8p4l9I+hD9wRnqU
         PhxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0LYaZjFOBKWTe5a+pCCRDbUaATojFag6cj5aSJS5XM8=;
        fh=jnuUOyxuXI8xDsjW9Q+/Ev44qiu4WYaulcPP3SLtynI=;
        b=hzS7N4hd60kiycTF1ig3jVzs8IQE/VgNj2srUGSMozfxEJkE4LyXrbZWW8o5cbih7q
         CyL8+nYonU3l+m9cO3i9jWSqrQRpSng0irhgi39XX/MYJaoseVgS39cOWcbv3mXHw/Jb
         HDLtkkv4NFeIm8FvXOb97a1ORNMX7gLMh2jGTfjeutFmYDPcd8ExhJ12GiV3DXzP1pl/
         5yitUU4PnxFoXV3Q/q+KhyssJ/rW/pqVizIvA8QSLPnNc2J8yILsSnol2xlRISj0zupo
         7uIlMR2N4gmH8VRbj7xxg0be5IroE7e6FV4J/uPiyzrThpUgN7axtUJB7xkILhvuySio
         Bhag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="quzc/mma";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718895560; x=1719500360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0LYaZjFOBKWTe5a+pCCRDbUaATojFag6cj5aSJS5XM8=;
        b=p+WI7x6we+xfwzrFvOnnYaK6MLCF5xQgpEuPkzMQiMEHx83oGZMYHIv8XQ6Xbg3NdC
         eA7pTYxiUM65he9r53/zJ3deNrMHwVO7IfeNDn6uoiM5SZzD65XGNsNbNpF2QOzfO0ig
         0t2zLYyHSLwt17Hf0lUKXQSx/oqCvXExNncwin5DFsUQ5Gmk2SvQS60cwb4Xkk2UgToR
         ExI5/HuSCzsatZnt07Yqqq63/9sj2bV33BS5703W0dAfRZsNdYnGT2gfx0wOLYUPprjL
         3N5qaFKcgYWGdxy2SlnQxKzE6rO3gjorjE+eVrradGlUy+4NmvCfBNQFUgIfb1seGmgy
         olUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718895560; x=1719500360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0LYaZjFOBKWTe5a+pCCRDbUaATojFag6cj5aSJS5XM8=;
        b=wvOS/FNdR2N7PbkkLE7NtYIwbgDbanr1WhZFX5dxAnnZu/eSZZ2ZRLP1jups8mOdmC
         DI7QSBckezvW1oL8n3dLaaQAE1zdKZJgsrOC+4kpXkkBSdaYuaQTCBVi1BKclJDTo6L/
         Dgs4XrFv8M2FeJKPs35U6N7kkIFB4lUwUIXGp0DTWKOwhGDMbGv6Jl4EDIx59zSClclu
         0/mI3smY8HIPvpv3FSjyshpE+j6KleuU9M/k+rd8MyHqmIGL6g+ERcpsQffFm8QjCx0u
         Sb3pOduoj41o4m3n0nnc4+ieGVWule02iyHv0/qskl5/Vt38uZf41/1UjKDm9f7IwupV
         woIA==
X-Forwarded-Encrypted: i=2; AJvYcCVpd2hqB3b5ibSp/+3tCt6vz2r2Od9o7dTjOUsrEM/VWULDWJyihVsTCq/Dmxe2Mg2O5pd0gqpUgjroHkFc8pyOyoNZKK3cxw==
X-Gm-Message-State: AOJu0YwhB6CWlzQ2w2O3DBhbM3sXL6fwxtv9Dkuw08hvSeVJPE10c+tI
	k/wm+0YBZq2FIzw1FihLRD7EhxumzO8beBWeqTUZEppWUzylnrsz
X-Google-Smtp-Source: AGHT+IElvYAUBzYpvf7oreRH8zs9m9FXqOYp6zuXchHc9AAzQwa3cyHyvYElKvx7W/J9DYHLebg8hA==
X-Received: by 2002:a05:6e02:1847:b0:376:1808:f8b1 with SMTP id e9e14a558f8ab-3761d76e120mr63638015ab.30.1718895559848;
        Thu, 20 Jun 2024 07:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a24:b0:375:c5d4:a300 with SMTP id
 e9e14a558f8ab-3762693bdd5ls7468005ab.0.-pod-prod-08-us; Thu, 20 Jun 2024
 07:59:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzIjTlg6f5QmvwRbbuOlCXCp+b8R+Dskze8ZLk4QiUWnDrucEPU4lyKsOHagIyNdlKr26XsUt8EPTCxNwSKzks/E4jATLRfzkokg==
X-Received: by 2002:a05:6e02:1fe3:b0:373:7f70:bb8f with SMTP id e9e14a558f8ab-3761d72afffmr67519865ab.22.1718895559138;
        Thu, 20 Jun 2024 07:59:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718895559; cv=none;
        d=google.com; s=arc-20160816;
        b=yhI5WL1W5Ot919FQpRTx12VfePYaQKC9X0QTKDqVePknIuHNHNzBdTjMjsaTCMt9LY
         2iO4hHpq9iqlz/uY+8t3qFdEZOhFS4aD4PhqSRcCGdqlFBtF9I7nk5pSSHNfW90+Nq5i
         9IwkLt0MocT5gPRCzW9f6oYgaCLTowxYRMPLb53/PaV0RRroCGExlpKR/TlbsW4U8wfQ
         Lx0nMzev5lFTQKs71tkQHMFxYj63OXpRSYiUN9iVyXy3BDm2ONmmwS3+b9u+F1IRnxkU
         LzNWg52iMeE9TILzqjIwHQ90VjJlW9FgzBkbVMxcSTWpK1OAu+t2yqe7NDi12G4lZftq
         nxOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wQFe7+FoQAQ/Ej8PGtCjqCQeTZhNJNzpwjveIE3kwow=;
        fh=oB7LPUX+2bh9ZntiJrTwb5y4SHxnpP+xLvwJ8k/K3Lk=;
        b=Xdnmz9uaamFjqKCSASa6Uki2X8nnufavrN/iNtpWr9CJjZ12AqldXJRxW5ydtGjA3C
         HJXeY4S/NOvn9KAA73heK1NbeKui+Ksk1y/ecIcP1GzPhEAYmqeRYCP3MfO11W1BfNdl
         cGXk+gt6gooSAMUlowSUkrvsUUdSLygzpU3zml0hFSe9I2uuG729b7NGmtEGK2HlNgFl
         0wK83H+uS34QQfOiPi5rqhsGFv7tKN3EHepwvwzCfrL9tRTtvIXhcZiPykg0Vj2nW2nN
         C8HSpYjYL7kU82141pIJQtNqrSr8m6LWwBxuLW5fWKTP2WZ9nSChDvUrHMQrVvLxXDNx
         yDig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="quzc/mma";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-375d832b32csi6196315ab.0.2024.06.20.07.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 07:59:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6b50aeb2424so5133056d6.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 07:59:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuxHinp+7wrEF3fYgcIAzxFFtHA0vdJdOkrMi/1ylehQ7mgQvet+AHS+aBRUOtNJAFjaAEoQj+VM73atk9dgPbUwFD3eqVxFxM3Q==
X-Received: by 2002:a05:6214:14e3:b0:6b0:914d:4a56 with SMTP id
 6a1803df08f44-6b501e9f7e5mr56738086d6.40.1718895558286; Thu, 20 Jun 2024
 07:59:18 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-14-iii@linux.ibm.com>
In-Reply-To: <20240619154530.163232-14-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 16:58:37 +0200
Message-ID: <CAG_fn=V2n_pwdKBK1jwvZ9Aw_M9-UgZ7xho2KS0uUddHWe6H+w@mail.gmail.com>
Subject: Re: [PATCH v5 13/37] kmsan: Support SLAB_POISON
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="quzc/mma";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> kmsan_slab_free() to poison the freed memory, and by preventing
> init_object() from unpoisoning new allocations by using __memset().
>
> There are two alternatives to this approach. First, init_object()
> can be marked with __no_sanitize_memory. This annotation should be used
> with great care, because it drops all instrumentation from the
> function, and any shadow writes will be lost. Even though this is not a
> concern with the current init_object() implementation, this may change
> in the future.
>
> Second, kmsan_poison_memory() calls may be added after memset() calls.
> The downside is that init_object() is called from
> free_debug_processing(), in which case poisoning will erase the
> distinction between simply uninitialized memory and UAF.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV2n_pwdKBK1jwvZ9Aw_M9-UgZ7xho2KS0uUddHWe6H%2Bw%40mail.gm=
ail.com.
