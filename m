Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZNPV3BQMGQEAZBKSCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 21BA2AFB023
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 11:48:45 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b3913a15e3fsf773397a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 02:48:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751881702; cv=pass;
        d=google.com; s=arc-20240605;
        b=LiTsSUoKVxTJ8KCJUyPXZte3wWyQNqPKnQkvRZ9gxtAyRIj40Jh+d8C4Vi/fThM/sx
         nEM1VT41J2WNQsKPQPg2rwsLAFP984PpvyrQ81PxKlGU66XAsTiKlRVdXBEocXLTKbJh
         nAQl2KzkL96WZqEFaA4LegjuD2CafTt0zPANbGvZH3r76sm8w/BrfLfrDOn4+li9g/l2
         e/etMbhN1mWYW8IPl/pDHpDtOLw3pQFNtjLDjHEMhis9qdJtcgXAz5QxyoysgaFAPghq
         Ym4LNRx3OvBudBg1rgW+WshS5ZrrqDGrNcsk7l4DVlWseqOM3kr/Wq9AOt+0bpA7L0i/
         IGGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YmLMZsRln2XFZgdaNauVM1nC/CmoM6Y31svdNjcDn6s=;
        fh=W1mfadBXSO5bT3ARGRQCxCNli5FeloLoec0HC5gdtbY=;
        b=VQt0nSHy4N1uHcGlnsinhqt94+rJy9xONWZDRIbfoR9c+/RkssnIu8jWI8Ct4ZJxIS
         mhmBxf6j4htEZIDHg0j4J4kSjoeAJftW0OrnUYC0h86JEFhlj327xJSCRRv5l17N1tP4
         jLF3/6v6RPSpfMDB8dTR32TSt7NjnywH0eGZsDWUTRdFCqkXBSAeou78VkAoodzXICTE
         EbZ9SnzZnh/Wu5BzdXim6TK6TTgaOnlYCAbjUT+YYgwERBpjFkNm6ZLe83TpxOyQmnMk
         9jLjDsMaxcWfVRkZnQNAXbghmEd1rR+rX4Mwqt0M1KGQhJMJ8pufwZ/aTAzqBB3glITi
         7flg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Px0fWGle;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751881702; x=1752486502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YmLMZsRln2XFZgdaNauVM1nC/CmoM6Y31svdNjcDn6s=;
        b=dnhB14BOeknARI8dPrbkGG2k8MxLaPhQzKLwK9HQ7pIN8ST2Ota4IYnA/nGyEGxM25
         UY7WDAUjVaZ6mzvZc1BMfMbSIjznEPMmOzalEAoinrySNkmSynSK1I8CUjyqRy9N3jIB
         Ypv6eKLAk4Z44PEfB9M67T6PLUYyRx03+kAzqZLlZJM6zubMmWLjHpH5thA6L6RhHHry
         Owk0EZDUHBk+64QBfGqpT2H/lQ5ZoFo4LziCt4UkLNx1EFLX2GKhF3gJxO+xF/NBz/C6
         oS00MdL3AEm98FZatpLVas9MN864Gx1/qYeTkTleGqfrVIAWUiiPmCR5LObzwXwQp8ID
         fvGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751881702; x=1752486502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YmLMZsRln2XFZgdaNauVM1nC/CmoM6Y31svdNjcDn6s=;
        b=SxaIWP7xY/1NIEn8VFh7mZbReMSBAJP/ytXOJKhvcJH8Vd/zL3afRIn2KBqCy3R/pk
         H579PeAL1jCyVeG8uyucQm3hI+3Z2L6N5vW/vJykXcs2DaIS/UYcebGINgm8dOObhpoH
         B4/Qhyy1sJ2mgvEJONPIuiuE1iIGvMEFXcGmc5W7wHV2RFJeq4mLgI7vHjqWdFikQXOH
         Mz6Q440fGGAs4jdz4ynU+be31CrLCE6pOKSTX5zwQ2olceXzWVNv7AosqzvUYXVJaal3
         sE9nJVkFY5ctnsVA78ax1Kn4w/2nkZUge75hTPggi0ApX3gF7f9q0D0yO/vtBK0sr7be
         OO3g==
X-Forwarded-Encrypted: i=2; AJvYcCVrc5rC7HRHt3u7g4xbUs4CAGj5PeofNCR47qX/9Uwd51AJrgkLamkwGieoQajgGihGmQqurw==@lfdr.de
X-Gm-Message-State: AOJu0YwibWfEHgpi/CIFibvojsG7cPE11BBWNsKctsBYvwxv7wjTwpTH
	9RdkGAWpKMnWV1hrMr5F6gifcOGJ2xK7Tyb6I3spxAf4TepLynH6zjzu
X-Google-Smtp-Source: AGHT+IEBzIbaKRrxk7yQAPZ/ZiGRNNO/me80TIcfzH8rlghbH3dEcgsYHUdREljYaLVK6WhdN7hKjw==
X-Received: by 2002:a17:903:1988:b0:231:e331:b7df with SMTP id d9443c01a7336-23c91057f45mr154502805ad.29.1751881702098;
        Mon, 07 Jul 2025 02:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc19CVvrSnPjtlIEnNXsl/WRtYT7tq01k7YeAlARU+/ww==
Received: by 2002:a17:902:d486:b0:238:cdf:5037 with SMTP id
 d9443c01a7336-23c89ac5153ls25529685ad.0.-pod-prod-01-us; Mon, 07 Jul 2025
 02:48:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKd0bif7BFvlZM2cQiJsYSdaIFguPNHdz0ztAEFcgqXADAMHU0Le0mtigqW+U9DIGXKLGT16ADOv8=@googlegroups.com
X-Received: by 2002:a17:902:d4cf:b0:236:15b7:62e4 with SMTP id d9443c01a7336-23c9107d28fmr121118905ad.38.1751881700748;
        Mon, 07 Jul 2025 02:48:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751881700; cv=none;
        d=google.com; s=arc-20240605;
        b=Lg0zM1Sjg/juZAnLacA22V+3ckh3Hu4xuy/LyhPjlF+XsaO3g+vQFRg5PKylO35YH5
         fWyNzt1l3NBowOMpHscboYoZpMjlOuHN4I5zvn5ELGtJgjArTuSHsDtkhasxORVvefFn
         GO1mk76X1npQRNko1h4EzmHb+Evyx5XhLHUkUn81Q4nX/xVIv4i2S1mzxULoo5HRcktB
         WugfIJzRBxbzMqijPnMIKgr9bNnwBm8L1ePKhGN4sa9Rnlv7O+NWbdfiryx25H8VrQLK
         ifoyr0hQVL7quRaFoWw99LMh3v0+5hlDzDkkujW5Q8NxDcL1+i/yBg8Dmx316x6w66TC
         3L3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=frbjbKfca0mgstlmUpI74NtNTt6lUs+p9/a8UNKkFt4=;
        fh=ZX7pdS+EU5ciUeMFy6SG+xUSb1ypiNEhSL3dkgIQwYE=;
        b=fZ4+VZtTeemUC/ArAO8x9Bl62akoTSbMhdcrQ6NakiTTEfk4a8Gwhe+OTpFbmZpthu
         pCo2EgJk4yb7/ZmorB34SLwmYrgopWCJkkPe8PO2k1jH84ciYgoS1NxjZRwaUXatmleO
         l0JG19B3VMJOPzyukVUwvd2LZRBYSzi2xE0yin3O5AOc70xwH5cBlHruuEXsYUAubwK7
         0G+22fklFokE8WodEwilRKIUJJcKVq4lc1H9YW9Ui/Wkmm2S9nPirjFDMP3n9jVVBUQ8
         NF+rB/F2YyK13bD1rvgih0AhGXhfNPZKUvFPRjb7byY9dp28B1vx6CEMhZsHfTew5Qz1
         RXBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Px0fWGle;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c845037bdsi3153075ad.9.2025.07.07.02.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 02:48:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-6f8aa9e6ffdso28743246d6.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 02:48:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqExKajS6VZ+tTztowigoYsG/9Jje2Qta0S+aP0VfD9PnQrreqasF2Kf9hXdYdsgHGmY2ezgfUELs=@googlegroups.com
X-Gm-Gg: ASbGncumE2fJe97bYOdRRwicZP+YuPG1EtLrzdyuwW06dJupHZaMFjuTl3ygGO7PQB5
	7b8Zu339GrSz3t0XtETXnZctl/r0azKBnf7Ekr1sijddJToDpSZ4CigaYpvVRztTUH6X49aeym4
	YEWuxVP6Nr9gcoY2nDaZIcdphAZXWLQLp+fmeuVkbxZ8KqhzbhU5+Lus9lnTEzcafEtiw8Hg7Fj
	A==
X-Received: by 2002:a05:6214:5d0f:b0:6fd:609d:e924 with SMTP id
 6a1803df08f44-702d16b5b13mr143596346d6.36.1751881699546; Mon, 07 Jul 2025
 02:48:19 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751747518.git.alx@kernel.org> <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
In-Reply-To: <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jul 2025 11:47:43 +0200
X-Gm-Features: Ac12FXyyIGAsATyNgJop_7rvBktTGUGYSMPyLaAqY218kgxIasAxME7dbvT6CZY
Message-ID: <CAG_fn=UG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A@mail.gmail.com>
Subject: Re: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Px0fWGle;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sat, Jul 5, 2025 at 10:33=E2=80=AFPM Alejandro Colomar <alx@kernel.org> =
wrote:
>
> seprintf()
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
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
>         p =3D buf;
>         e =3D buf + countof(buf);
>         p =3D seprintf(p, e, foo);
>         p =3D seprintf(p, e, bar);
>         if (p =3D=3D NULL)
>                 goto trunc;
>
> vs
>
>         len =3D 0;
>         size =3D countof(buf);
>         len +=3D snprintf(buf + len, size - len, foo);
>         if (len >=3D size)
>                 goto trunc;
>
>         len +=3D snprintf(buf + len, size - len, bar);
>         if (len >=3D size)
>                 goto trunc;
>
> And also better than scnprintf() calls:
>
>         len =3D 0;
>         size =3D countof(buf);
>         len +=3D scnprintf(buf + len, size - len, foo);
>         len +=3D scnprintf(buf + len, size - len, bar);
>         if (len >=3D size)
>                 goto trunc;
>
> It seems aparent that it's a more elegant approach to string catenation.
>
> stprintf()
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
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
> detection (it doesn't need a check >=3Dcountof(buf), but rather <0).
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
> @@ -2892,6 +2892,37 @@ int vsnprintf(char *buf, size_t size, const char *=
fmt_str, va_list args)
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
> + * If you're not already dealing with a va_list consider using stprintf(=
).
> + *
> + * See the vsnprintf() documentation for format string extensions over C=
99.
> + */
> +int vstprintf(char *buf, size_t size, const char *fmt, va_list args)
> +{
> +       int len;
> +
> +       len =3D vsnprintf(buf, size, fmt, args);
> +
> +       // It seems the kernel's vsnprintf() doesn't fail?
> +       //if (unlikely(len < 0))
> +       //      return -E2BIG;
> +
> +       if (unlikely(len >=3D size))
> +               return -E2BIG;
> +
> +       return len;
> +}
> +EXPORT_SYMBOL(vstprintf);
> +
>  /**
>   * vscnprintf - Format a string and place it in a buffer
>   * @buf: The buffer to place the result into
> @@ -2923,6 +2954,36 @@ int vscnprintf(char *buf, size_t size, const char =
*fmt, va_list args)
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
> + * If you're not already dealing with a va_list consider using seprintf(=
).
> + *
> + * See the vsnprintf() documentation for format string extensions over C=
99.
> + */
> +char *vseprintf(char *p, const char end[0], const char *fmt, va_list arg=
s)
> +{
> +       int len;
> +
> +       if (unlikely(p =3D=3D NULL))
> +               return NULL;
> +
> +       len =3D vstprintf(p, end - p, fmt, args);

It's easy to imagine a situation in which `end` is calculated from the
user input and may overflow.
Maybe we can add a check for `end > p` to be on the safe side?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A%40mail.gmail.com.
