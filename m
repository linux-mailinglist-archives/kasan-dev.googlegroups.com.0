Return-Path: <kasan-dev+bncBDW2JDUY5AORBLHKZPEQMGQEJDSDIXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 10B00CA816A
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 16:07:26 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4779da35d27sf29158665e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 07:07:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764947245; cv=pass;
        d=google.com; s=arc-20240605;
        b=IL/Yh7dS1eKSWW19h72AMftMbqMIA4TRbXs2bWgBK+G57sTZE5lTZ8LjEO7BXpoMrZ
         ZPt6q+JwXh5fz16/dy3FoMVB/a1q0r8UEx3OyMA6bN8iCyfzsQ3NHKMlN1dOgxze5RYj
         8g8/+5lvzP1k6d2+A70nS8ILl7qbyoPv3esBCB2KygbQw8iHezT0Hy6lTXzpkZX0UW5j
         FP4md+VP9IcEq6qTtKk8wbix13bM9Pxypc6SzvYVP+EQVGuTaATgXu17nB0u5rhunnpC
         KtdBxwKP+Y6lII5PxMCYyArDz1EgkO2/XmD3WW2XCzhwY1Y9TD8iRiZH7iocuYaTzBgm
         +ZIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ylHh9Vwe1QXruasNNlxYfVinXMTKcmaBolJzEMY+w38=;
        fh=NMsxpPmld4zC+TOBL1msMh3rGgTltLA5yKV6Qnq6k4o=;
        b=R+5VBQqh9TcLokYOqbcd0/tScc7PNAk5v7RD5nzRVraRVJ92+2Kf5iXgMZ0cOcfOVA
         N+Gnhm0q75vUQwPRDvcL5LBQcJAly8+HrmcKJkzmfybzw2LdXUF3DgJtR3G5pN3VkdE0
         4jP9oTWikHfLYVXawWRdYL7iuNDN/XoRsGYZEoni1O/hmxQijbVahC9QCTVbtN22Leh4
         yXhwJJAi44tOO+WHpomB1N/vwsYJzMraLUdH2Drhoku9XIjy/Gkg/6i7OeIC877dVvAw
         NNo/JJ11CZ6iaWuzTcH69gXHeHHR9isodFMVpcXV7VQkQhZBrBXI+dUfhWHza70STw6T
         xtmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fBYiTokS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764947245; x=1765552045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ylHh9Vwe1QXruasNNlxYfVinXMTKcmaBolJzEMY+w38=;
        b=pxocd7SttcmDeDBLgpo0uF+jwHeM/CrRUZgw5C3ZJZNT1R5IBSZpYEsJJu5+z42Zwu
         wRcl5a+i/nDhAmq/6pvonYprHg9ZyluHcMvfuh/hQVv6qECiBEKSp82RzfD1fPyZio1k
         FQ6I1SBxFKITM7CMRoHWjOtU4KTaOXq+1hRtu+Fl5a8krZbEK7DDCugoTFRcJcx7sILY
         E/QrgER23NaGq7AWxTNcfH+ghLhIDWo8szWskh9P8i4wHLN3mPvCv7pUT91sLH/8dn3S
         ayXe6dZAJwuzhmQynh57/Yd4qdRmFF/Keio1fq5CrTOjND8LF2phr4HN6wQhO2KoIOHB
         ryCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764947245; x=1765552045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ylHh9Vwe1QXruasNNlxYfVinXMTKcmaBolJzEMY+w38=;
        b=P578HXnhclX0l+sAbVL7LZobutDjzNvLFuS0TZjSQfnqPOX5gMKkv5uqy3MCt2BM6W
         nbg8BnmaAJ558nzzJGIymqO6wfks5h0TFdRiDFGim6C+T+1zupxtqvgaYnGpnnrP1cIQ
         +rzK2sxKINq5Ytn6SVkpKwzVJ+0OgfF2f4Wo4hYUD+9l2FaDbJx4lWC6Ybk4cf1KkuRh
         6JwPgwiOMhN3+emF3fa+bmrIifK0lpiwQ/4OmaYTz1VeAevMc0+9yEbbwOGEq3IoZBqa
         /eLQNFsnOv0P19/9oDaC+mDejFxN4RHuyQOFyeTo6uvHV9+plIDNg/lijkqUQg8DVu/0
         T87w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764947245; x=1765552045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ylHh9Vwe1QXruasNNlxYfVinXMTKcmaBolJzEMY+w38=;
        b=RmccsYhKfXL+kh4LootZIrBkS8h75sV6qwo5H/GFmWS7bRpjVNFyM1h+oVJwIWYKY6
         VahqK5+jrsPmDd9fa+TgrrURfM7kgWMc5YzToXPw0zPptgTqEwA2ANblxnfYSvHCDPiJ
         yvjhv5fdfXGKirPBX4Ql/r40jFclTox3sOVZ9paso792ctF65KJf3Y0mhyw6pO0fsN0N
         +DTRsqTh2zZ7S72X+LHvfaR1ahy2vzQz41sZNA/Lqycisyz5HbivG6KrJZqoc8oFBoxe
         SKUFrEFEL3icfi1YMkwz7XefQDl1nG+2YpEmYZr1iSwSnQGiUyprDEpn1iYILsotMsR9
         TtNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURxRDqMU7lwhrjY26BKq1Mp+GxHfsH4FubAZorD1tB/eGYhd9t5+flxbhC0fEJAEwZ7mJ60Q==@lfdr.de
X-Gm-Message-State: AOJu0YwTl7Lw6B0DYkT2vqmau3nLuovE561hEXIV/WXdxMdzAZVQZmP+
	TRwShbB4mfwKZxKNxSUihfKy5oYPCkcB1u/wNI24ug/kFcrEJgfAeiib
X-Google-Smtp-Source: AGHT+IE5cnbS34+5O8Ko+bZAoTIuQxZej5NuqSHOgPJNb85xw/wj1jBgKaWoupQa8BQcv8+7NXn0Yw==
X-Received: by 2002:a05:600c:45d5:b0:477:aed0:f40a with SMTP id 5b1f17b1804b1-4792f380adfmr79144455e9.19.1764947245241;
        Fri, 05 Dec 2025 07:07:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b2q30ZfP1jiJJFn27bWYTcmftVAVTZE7wrkQO1Yqjk/w=="
Received: by 2002:a05:600c:468e:b0:477:980b:baeb with SMTP id
 5b1f17b1804b1-4792fcd3171ls18209335e9.2.-pod-prod-09-eu; Fri, 05 Dec 2025
 07:07:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJZAf2V3rPAKUWffmR/YIfhG8oXLcLrTn5DGQ/PIBgRxbKyA+nhQomisWe2WPlSnu0Vb4xPkX04Wg=@googlegroups.com
X-Received: by 2002:a05:600c:b8d:b0:477:7a95:b971 with SMTP id 5b1f17b1804b1-4792f39849cmr76677465e9.31.1764947242290;
        Fri, 05 Dec 2025 07:07:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764947242; cv=none;
        d=google.com; s=arc-20240605;
        b=V14ln6Kc7hl0vPxXU5EZKl/JjLdYFHatOo/sHgldHBTosOg2+fdsi+7+RW1ZqM+ziu
         KHDwTdWYlzA62A62BMciBrA9AROtv1oel3vGwBJX8eyX8abKrmZcqsDorHLPwsay6rq/
         T811gIeQYAMbquj4ho1Pcoc4yXx1ApF26uFt/Iclhi/KGhT1ui0wljRYHnvuj1lhLtuM
         N4zw0vhlv6tlshr+kFypv4UdTlfurCeSz8mE2OjVtIx6opvhXCdt3K9VbEB9Ny0eSRIK
         f500AHOvq4ci5fWCItIpZzzGp16Ivtetc3KsnlTOejjrBLelx6XVHLdGljDi1ynMS8Fu
         kotA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5e1JDxNMsKeBjrN3+x94DCexyw30V6kM+/jaZC8wkNo=;
        fh=1gmimDbKZt569JhuJQkTIzXTsSgIQ9jLyFsxd1SvkPk=;
        b=K0Af8O3wiSgW5OZ+hhC3si8T6BRVYPZN/e7wEDYZzhzbjMS+wAu1YyrYWgsCkd2KlJ
         guEtt8A0lSXPJaopNYM1yQNI+cznU4nP8+MBdbbCMPkd5kkaUUKqr0W2jNFx3H9KPYel
         A08Cc3TvY6eA2le12qA0OvRIDcb2BWs+hJb1yz1COavqiioklButsqc1rJzpmncV2pt1
         lc10pzytLBKJ6LscbKlsGVLrK9uB8j3OaxmIjUJxFMMtznicMItHXFQ+Vi1vcGGAWv5Q
         ofKmHNTUVYBBNQCdKhF2rigP75euon1XctrWqX45oskSnelXdeKMaxjTn0FHv9BAA162
         pEqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fBYiTokS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7cbff4c3si69477f8f.5.2025.12.05.07.07.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Dec 2025 07:07:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-477770019e4so22433885e9.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Dec 2025 07:07:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXov4qhM4bzCS5ia/fgP+T7gjBH6R8ZS4gOOTndzI7N+Ykg+Tpf0hiIhPZRkSOWYjo6bx37A6I1MGQ=@googlegroups.com
X-Gm-Gg: ASbGnctVHcdVKxwvzdedUzJx3kD2QvUtIoii4LAFut0AL5ztU0BOXY3OMj09JoLek3B
	XkxcjKWkRQ99F4qKJd4jFlmkdb3dRBYWNkmAJNyyKiN8RW99lIMueP+oXt7PGEH0q6+HBWHu5p/
	VVqw4duJ01RJUaVVeFKeJz+0L7bxWFuOWCyzhwEmD4He8eJuGbNMOz5g1ChlaI5MJ/Qk2eQkjaT
	5PkCf53hLlBaGlBJ7eD+BjoS+to2M/JvfwAhpzANYFG1pU2NFZgD6ai8x6EnBjj7YvLPJv/i8Pa
	ixvZ0a+F5a3j76X62vqrQuDtLa/Wswr/Hg==
X-Received: by 2002:a05:600c:45d1:b0:471:1435:b0ea with SMTP id
 5b1f17b1804b1-4792f38d501mr76181395e9.24.1764947241641; Fri, 05 Dec 2025
 07:07:21 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-2-bhe@redhat.com>
 <CA+fCnZfDYHUVKX-hdX3SgmuvJEU-U+MuUJGjs-wJJnfRDHz2sw@mail.gmail.com> <aTKHzmxR3JA2R7qD@fedora>
In-Reply-To: <aTKHzmxR3JA2R7qD@fedora>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 16:07:10 +0100
X-Gm-Features: AQt7F2oIzOZoI9YYmMGEGfR2euyjD-iV_heXJVsHmHq5B90kIr5LFLwzTYtsmlM
Message-ID: <CA+fCnZdZQFVBf_NkrKk0U+TAptfi6RRmCkPY5ZpOUeObBpwAnQ@mail.gmail.com>
Subject: Re: [PATCH v4 01/12] mm/kasan: add conditional checks in functions to
 return directly if kasan is disabled
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fBYiTokS;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Dec 5, 2025 at 8:21=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> > On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wro=
te:
> > >
> > > The current codes only check if kasan is disabled for hw_tags
> > > mode. Here add the conditional checks for functional functions of
> > > generic mode and sw_tags mode.
> > >
> > > This is prepared for later adding kernel parameter kasan=3Don|off for
> > > all three kasan modes.
> > >
> > > Signed-off-by: Baoquan He <bhe@redhat.com>
> > > ---
> > >  mm/kasan/generic.c    | 17 +++++++++++++++--
> > >  mm/kasan/init.c       |  6 ++++++
> > >  mm/kasan/quarantine.c |  3 +++
> > >  mm/kasan/report.c     |  4 +++-
> > >  mm/kasan/shadow.c     | 11 ++++++++++-
> > >  mm/kasan/sw_tags.c    |  3 +++
> > >  6 files changed, 40 insertions(+), 4 deletions(-)
> > >
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 2b8e73f5f6a7..aff822aa2bd6 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -214,12 +214,13 @@ bool kasan_byte_accessible(const void *addr)
> > >
> > >  void kasan_cache_shrink(struct kmem_cache *cache)
> > >  {
> > > -       kasan_quarantine_remove_cache(cache);
> > > +       if (kasan_enabled())
> >
> > Please move these checks to include/linux/kasan.h and add __helpers to
> > consistent with how it's done for other KASAN annotation calls.
> > Otherwise eventually these checks start creeping into lower level
> > functions and the logic of checking when and whether KASAN is enabled
> > becomes a mess.
>
> Not sure if I got it correctly. Are you suggesting it should be done
> like kasan_populate_vmalloc()/__kasan_populate_vmalloc(),
> kasan_release_vmalloc()/__kasan_release_vmalloc()?

Yes, please (assuming you're referring to how these functions are
defined with all Sabyrzhan's patches applied).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdZQFVBf_NkrKk0U%2BTAptfi6RRmCkPY5ZpOUeObBpwAnQ%40mail.gmail.com.
