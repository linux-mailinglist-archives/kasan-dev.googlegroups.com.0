Return-Path: <kasan-dev+bncBDW2JDUY5AORB55Y3KUQMGQE4APTCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 651E67D3C0B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:16:56 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-581dc6915b5sf5583646eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077815; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZDDeOcOJPL2jBbghGJQiEtuik0tHjjDzHSN/+08wIDpfavhp7b2x2jiSU6tK4NWZJ
         smYKYBUCiICA9ZOk2W95n53fq/jjCA+Dy8A1CJl3QpdVIVp8+Gpyk11wzFb/AxsBKWLI
         zlLNZMhTdHg72NFZMRrzcONKQ7MMqNfsaoXOfdEpSvRU5aCRq1uDwobBGwVFfgyn8Z96
         tqtjF44bYfPmA9Mlmn4mOWJ4rCZc4Gly4uj1TaMfmkeprNO8hDIUgduZWLztMoGBvFjT
         KzHlMqrLq10THQU+DpH8ZojSBfHWK6cXNnwgQlgR3HEHyVqb2yvZYcF2AKEloz3Uyb+q
         Ofdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1Ysp6iILXwVJGap0sx4GBsfj3NEh4jeamZ7j2CBbtkw=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=RjumyWYK+Ht+zPw/FpWjjD/HQdegXsKX5KMbnaukt6AdGURl525XaP+dWMhXjv/z3H
         omrpbaJpc6SxvEemjZIwn400FApxfCeOqe9iOBBvkMX2+EPatUoZdNbDZt4kaXkp8utY
         4ByJdkmOtozjNYjARsz+Wgw7KGYoy499GMb859MLkd2tsBUYGS7ozryP3Fh6fIQ26W3Z
         nMSIQ90EOzFCYZubZfosluElHqB+M1hn17DXZ347xRyPTyMi/6NRlYFav55RuVxjbvn6
         5bhpe6HC58eA3+x2re679IyzewTV/w7GlqChiBpOdafg5z1q3PhZNuDr7DVesk/96Ik5
         b8iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Udx9XiZF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077815; x=1698682615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1Ysp6iILXwVJGap0sx4GBsfj3NEh4jeamZ7j2CBbtkw=;
        b=OtUAj+gBUvNuq7+BiqRKJbVski1e7Wo4mVTZSgl2Q+Ayj9j4quf0T1cz5YubhaWcU+
         Odvl7rXp20opNRw4/zPxMp2KgIkt+Z/wuEKSxLINPGagfIxygHrRQi8oKo6JE6OMof0b
         rwBrdKIM+EErhZNaiUCpRGqlaIJCb19zgfZc2M8eqsIc0iAbBXWuMtbBk1tyjDq7dK2i
         pH/SvSp7DaHJibwMGsVp/B10MOqveM+4DwAk+275Z+LOrv9Db/AihAq4QZj2M+lJBcfV
         4W+eQKrQAGrhK4z/N+cOM+xqP4+/9d6IxOGDlgtW47ulsK0v0m5blWEvqgPlYoPHiqTd
         q4Pg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077815; x=1698682615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1Ysp6iILXwVJGap0sx4GBsfj3NEh4jeamZ7j2CBbtkw=;
        b=NWfOKCWt+ocYknlKY673jStY/mZrfPm6/FAe8VbwxWxTcsrpmgzaHxQlenCXdWIcbv
         zVvdNFS663Tvc5sYgI2ObMuDOtnWLbJ5j0OiNGZi1Qg4a/XWwZ6AR8cVM1xWaWxqtO+W
         ODenYQfubylpDe5MWNHAka0/UJHsrq1dkrk94oAHTTPEomUkQ0N5x/gFtoWSrE2+2BSn
         S6fjw3oYcOePpn9pcsNfZr9a49XBBIAY9ijPsFbjaLKaHaXUfewgZEf0/11N2aGLqfFR
         LJwX7yCrf2jYLMchvjgdqvZ7MW0v17TVwVTGpuVZpdjSSAg16whxrnZZolarh1BBsPMP
         XuQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077815; x=1698682615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1Ysp6iILXwVJGap0sx4GBsfj3NEh4jeamZ7j2CBbtkw=;
        b=lyEOMZTokZV7CdKnBRzo3E2qaCdzvq3JWL8WUMDfq4btaZhtn40qVLzk7/JimustxO
         u3ZKwE5QstiNcZ+eStgb5HSkSGXc0KOllgSvfRM97ZRRo+G8+LlereagLa07jSvDI/6N
         w9egpFrQrK7xm+sRm4sU9Za9j5VqZ9QMcMFUrQIh1KiHMeX6w2qJvm8JjnEaqcTlcvly
         xxlcFRFnKgX7e+fv9q5Um1bJIPl2vIoXyffK2IGVPkZjjOTFDqQuhCHL+LSZpbt+1F5u
         HqMTz863tpLxSnhMWKWhrWI10iAVWsgLCdA+XEfw9shRzJ+d2TNhmhwRxI7c6Q/y233Q
         gVpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy5Tn2yesY5Lc+3gw8zKYRG/XOUxHIJxU3hBKx8dgAnLwxxqCIe
	XxdO2ovnttdNiez5wM+p0xw=
X-Google-Smtp-Source: AGHT+IEKGrFvI4Mb6b2mOrYlXAM5Xma+L9sN+c1xCOsjX31ll2jwtixnNUTHSc2AQtGCQtlRYNzOwQ==
X-Received: by 2002:a05:6820:1c02:b0:584:1457:a52a with SMTP id cl2-20020a0568201c0200b005841457a52amr9434220oob.3.1698077815222;
        Mon, 23 Oct 2023 09:16:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:33d3:0:b0:581:e7bb:9ad5 with SMTP id q202-20020a4a33d3000000b00581e7bb9ad5ls415729ooq.1.-pod-prod-07-us;
 Mon, 23 Oct 2023 09:16:54 -0700 (PDT)
X-Received: by 2002:a4a:e8dc:0:b0:573:bf68:8dbc with SMTP id h28-20020a4ae8dc000000b00573bf688dbcmr7726283ooe.7.1698077814336;
        Mon, 23 Oct 2023 09:16:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077814; cv=none;
        d=google.com; s=arc-20160816;
        b=NqGHVtPbMn1PCrtrU2N9t5lKgpFXgBz1Vwr6aaMQt9a9N7V3mHZvlUIkJWuZsn6Erk
         4pw6EB/zAAi/3JSKq3rP1CZ9sUubf9AluR9/Oer2U/1XFqkyUgoadT9lfNBKRyWnqHTi
         drGB6k7W1a0Sxfz/rA+BubRnLzr2FBSvAq5+Mfz1K4fMY3Rw/G5XehqJN/eD5z85gQCW
         1jXyoeWofKTvjPPqCp3nP+hwOglxWBEA3u4OOT/66l7FzNuXPMEr+nCSyYsmVLg+3AcB
         Jw4Q1MFU5Z6SsSc8iJ1AJIGLh/CFxcIMb8T+Jdn9A6kGTVgCBMJK8Zf6VMFsLGKT1dfz
         Egrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9tHn32Hb+H9q5/wYxwsubEfubdWSQHXuWNQ2b+po3Bg=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=HnUN81MAS5rmwbd8W1fzYbkJEreUmjn7CL8p9x5cAKfognW1H4xbohnzxDkiDqloZo
         OVYH6xWpqsHgIZ8iiDDtC4hP4tYW1xk5XX3zaoW+0wmbijcMs1B4PYikO4iOP87LWzUL
         MLu8Si6dmIINwFgqDbxP/HKKM9qEvU/ptrzoc8YpLX6ld3AbtK/w47BNnjSNRzJUb2yK
         99akTG3+bgsaq9/ubRW6ZR1EAB4ehPtXd6wOD1ANuTm7PHzECGLAjtLA9+V4b8GSRU0D
         iItDma7oRRG7zEvfPIdMNIy5ycsM+7RC6nQFaxnTFvtU+0Q3kIUO9JSKY3EH6mqL2esc
         0dHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Udx9XiZF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id w1-20020a4ab6c1000000b00581f123e47csi544649ooo.1.2023.10.23.09.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-27d292d38c0so2193946a91.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:16:54 -0700 (PDT)
X-Received: by 2002:a17:90a:b903:b0:27d:5504:4cc8 with SMTP id
 p3-20020a17090ab90300b0027d55044cc8mr7495426pjr.9.1698077813463; Mon, 23 Oct
 2023 09:16:53 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <5c5eca8a53ea53352794de57c87440ec509c9bbc.1694625260.git.andreyknvl@google.com>
 <CAG_fn=VBAN+JPtqRRacd69DOK9rZ-RMpzn+QDJTsZgQ68sOS=Q@mail.gmail.com>
In-Reply-To: <CAG_fn=VBAN+JPtqRRacd69DOK9rZ-RMpzn+QDJTsZgQ68sOS=Q@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:16:42 +0200
Message-ID: <CA+fCnZfDRx6VMSevQKfYYwCj49iqsKMaPaWt95rug-nw8Pgx8w@mail.gmail.com>
Subject: Re: [PATCH v2 11/19] lib/stackdepot: use read/write lock
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Udx9XiZF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
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

On Mon, Oct 9, 2023 at 11:45=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
>
> >  static struct stack_record *depot_fetch_stack(depot_stack_handle_t han=
dle)
> >  {
> >         union handle_parts parts =3D { .handle =3D handle };
> > -       /*
> > -        * READ_ONCE pairs with potential concurrent write in
> > -        * depot_init_pool.
> > -        */
> > -       int pools_num_cached =3D READ_ONCE(pools_num);
> >         void *pool;
> >         size_t offset =3D parts.offset << DEPOT_STACK_ALIGN;
> >         struct stack_record *stack;
> >
> > -       if (parts.pool_index > pools_num_cached) {
> > +       lockdep_assert_held(&pool_rwlock);
>
> Shouldn't it be lockdep_assert_held_read()?

Indeed, this is more precise. Will fix in v3, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfDRx6VMSevQKfYYwCj49iqsKMaPaWt95rug-nw8Pgx8w%40mail.gmai=
l.com.
