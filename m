Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEPYYSLQMGQEZMIUC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F04058CC3A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 18:38:43 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-10e7c0845e8sf1942024fac.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Aug 2022 09:38:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659976721; cv=pass;
        d=google.com; s=arc-20160816;
        b=IEaSKig74eEyyEXmY7HNsJ4+AronGaq7EzN1LLnbWtlTJbx4pyDnmjmWs4abKJ7Ikp
         +JrzRryOxT7Epb+ttdnygBRIfu71u+1hd+Ul+eUC0J4Q6mCCrQNs6G87y8fLv0made33
         JYYVY62C9Ot0Je1wzh7wuOmhG+YqYrH9tthAhGFygu8GNL/3Rq6ICLqBGSan8BrqwEk+
         m3V+RknqSXw8qt/7ZASUL+gRMqhQf1q73wNxuznLeomdJTYM0wOgMhJczgVjj84XSrRF
         dvmyE5Z7yr5UuiI/zjyOLoEjKcFZjcFfKL0rkwegTWEIU6KAc6JOnXtWERc3+dgFdi5l
         5mPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=u78SvZLBRtfSqHUFQtW8G0opXZgSDly7rxDqbRQszAI=;
        b=A30kGamvD64PwNFeodLKhcp1tf1wcmUuIxozNhw4JVegfMfavn/cXvdgyHrdRmT6J5
         FFry7I4CwNSgaSzKUjg6tAzQGbJHKAdgys20IY09OBW/i+havrUkIhZqGIoFqTwSWhVt
         abP4dGOx+RFdFPgeiI6ULeWA4fLPfNoUm1cgACgvBoFli4X7haC4B26oti3z0zsFBgQC
         rbuxi9ynbfA/O7ccklFGAkJteCEuw/TnJFtVfQxNRsZDdKWlv5SYUqpyVmPW3h3B6uoz
         zZpD61EYMu5uw0LWM+BjRvZHKEfiukJQ3W5fkvb2/ljhBK15jFCzAEWUeT8VI38Vr/oy
         VzBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RBd6EjHh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=u78SvZLBRtfSqHUFQtW8G0opXZgSDly7rxDqbRQszAI=;
        b=LwMtNRlT7Jir+rYkL4SASANCukASZjo721e31kTw9fvLxEa00iNDnDxtX5sBXYFUTc
         WKVvHDaeFjW00SoQPgePFYH0vrEuZAv7f327rpFO3BIAmNaF43PIG1vHaYC/2HIasBWs
         4kIa/+GG78XIj2O7mnY6ZNhhwbGv1h8Sz3OwlspAdFtIMFrEXa87YEIMYT/Ld+a/yn3I
         73DvkTGVRhz1HqgBmtq65TAFJzCLewvdCLc3HNpePXH2WUfk6lcSY64ORFWycrQdrP7e
         uJKbyIzdlwUjFrGbXyUoCt5GnQdj6jx3ZG8Qa0n60IyFlMNaxOpqnMvmW4gz27V39/Os
         zUaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=u78SvZLBRtfSqHUFQtW8G0opXZgSDly7rxDqbRQszAI=;
        b=3fYQDGYja33KmSdTP8Sth8I++tb4+PSEcM+HHOuaQFllB259yK1pl67KvmqROkq8nk
         KTeWF+bePQToJixdVASHfgb3NKsJ7lScQrUY0tUoCK8393b4RBzYQoEqZJVRD2GI01j1
         T+C6EOk7m+OV2zYBX+5c4gz78wAXE3203HSnU9+NFUY9xaHRZ6klSB9dQj+ES204AS5E
         dRjnb0hbjDo3SQoSaw5hI13pMRuBHhN8AKgDsfyY6/zgLmYCTBTfzgSMtUcBtnmOWpXd
         Mpwa7WPoqersEkn8C6pqHWpsEwu5c/zkJWCZyUGmMwCp8oAicvPLenS+fpI8gyYqFhxQ
         1aLw==
X-Gm-Message-State: ACgBeo35lLADx4ZFhvHHmm9Q2EfHZa5x+FkIXUKWKFqy/SO+ti+Ph5su
	0AROK61bNLoxdw7h7ULbmdY=
X-Google-Smtp-Source: AA6agR7nADQiQt0jM7aV3b4FAC9zathef6HftPwGFOLnG463lW45f3WleL3YgcCPajglAEXoPfaZvQ==
X-Received: by 2002:aca:3406:0:b0:342:df64:408d with SMTP id b6-20020aca3406000000b00342df64408dmr3644957oia.91.1659976721630;
        Mon, 08 Aug 2022 09:38:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b356:0:b0:32f:284b:d8d7 with SMTP id c83-20020acab356000000b0032f284bd8d7ls3321512oif.10.-pod-prod-gmail;
 Mon, 08 Aug 2022 09:38:41 -0700 (PDT)
X-Received: by 2002:a17:90b:4b4d:b0:1f5:164f:f7c4 with SMTP id mi13-20020a17090b4b4d00b001f5164ff7c4mr30311984pjb.131.1659976710725;
        Mon, 08 Aug 2022 09:38:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659976710; cv=none;
        d=google.com; s=arc-20160816;
        b=vQYIy+dmTkeqnCCEjiiiVV+aK9WMgeM1eIfu9G5EO6imKUGu3iUwveKKRXOzQLduIP
         DlQeTmdRc1d9eTXjZCoJ/G3EFv/aOD4BPyCMKkMTq0vGXkqCHhRvUTJbrjtRXEYwacWC
         Pxu7gMb7EwNcGeLEoMWfBVfsCH+npyP2Fpwqwl8C033C87Nzt4EPkVC/dKmmGDHYtrJX
         dcB1XPrqJZQZzuKm6VFI4AnfsdcIT8aOo7IEycPaKqWseYdIShRgeFoeaQsopHgXU/8Z
         tiqKY8TKADV6f5/MmBWbTWHndK3xq47JEmrBMcAvbvC+zzXlQ93QaKOD2go32QGLEGfj
         EzmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XquYmP+vX0zNQXcxrD0gfmPbv/22szoR0PAdjI6c6FQ=;
        b=FFRz1xIt5xX4Rvg7uOkrtyA0crCGZL12HynQpb2N9pdMLtUc5QWR9jzOFkgAow6EYX
         24KgBWILazV6Pc3gkNwxIxiDEFgMWUlJuSi8ufSA0LiXtzzEk8dMwuNY//l8QyfE+pnt
         uXr8Dj+S3MlV8uEs/g/QPtvkw4MCZuImXWhCoHQvX9M4iB/DV2NvkYUB8UpNOvyDuC+4
         j889bhpeDd+jTNb9KAz8N3VDU6AyO2lfUXGbD7R+WjPjVexMCs6jfQr4vdH8WveVDUvI
         U56ombNlo2sviO2G6Pl3z20rrxHh7UgmZ8ZmW8jgdSmGY3B5EJmvH9HN2qaz2VrshzGv
         GL6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RBd6EjHh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id mm2-20020a17090b358200b001f33d2b93basi707903pjb.2.2022.08.08.09.38.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Aug 2022 09:38:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-31e7ca45091so86959947b3.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Aug 2022 09:38:30 -0700 (PDT)
X-Received: by 2002:a81:7586:0:b0:31f:658e:1ac7 with SMTP id
 q128-20020a817586000000b0031f658e1ac7mr19730600ywc.295.1659976709754; Mon, 08
 Aug 2022 09:38:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
In-Reply-To: <20220701142310.2188015-44-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Aug 2022 18:37:52 +0200
Message-ID: <CAG_fn=UF0+0EAJLx=tW=RDoFxuY8qd=bHcH362-kxMhOhKVFmg@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Segher Boessenkool <segher@kernel.crashing.org>, 
	Vitaly Buka <vitalybuka@google.com>, linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RBd6EjHh;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Jul 1, 2022 at 4:25 PM Alexander Potapenko <glider@google.com> wrote:
>
> Under certain circumstances initialization of `unsigned seq` and
> `struct inode *inode` passed into step_into() may be skipped.
> In particular, if the call to lookup_fast() in walk_component()
> returns NULL, and lookup_slow() returns a valid dentry, then the
> `seq` and `inode` will remain uninitialized until the call to
> step_into() (see [1] for more info).
>
> Right now step_into() does not use these uninitialized values,
> yet passing uninitialized values to functions is considered undefined
> behavior (see [2]). To fix that, we initialize `seq` and `inode` at
> definition.

Given that Al Viro has a patch series in flight to address the
problem, I am going to drop this patch from KMSAN v5 series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUF0%2B0EAJLx%3DtW%3DRDoFxuY8qd%3DbHcH362-kxMhOhKVFmg%40mail.gmail.com.
