Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBFEYX7VQKGQEXC3OFOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BBFB2A85AF
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 16:37:09 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id j9sf6778009plt.18
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 07:37:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567607828; cv=pass;
        d=google.com; s=arc-20160816;
        b=YlCN+GcT8CRAeDI+NIVo5kKEMQHKBcCe9kTNBe44af28enfpcrhfCyDh3n18ee+q0W
         WUnDg11wMWhzSRIPogTIrbMpw61DWZN2VJOXDWyEh2t1N+f69yd22cCQ4mQ/9FUTieMV
         pCjAwxui1KRUKN4b1mVKf5WPsTALwYbM5zkpi3U4IdC+50syJih6kgWhIhGAnFWfUj9d
         YsxuaIVtmyzZOQjOpNGXexqWGYk/3ciP74npYTUu6EGymTuilQPo0Gjvn1EXCaDjUx68
         xtrjFNfIseWZvI6ioGUds+iHftAe7AuC3k7FTKW17y1cjRTYeZhQyuBxuERAxSjT7G22
         fZxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=iefNICkzamusZsp8DrERyGtfggk3tJ0fgyIO8QlUG9Y=;
        b=cCtnZTGVOplLLRstp6hIl9ZdmyO/okInclJanSSrOXS7I32az7bCCSOP9fGnTEftnr
         63/lCZ/qHtRhZLAV1SJKI2feW9Ys+4f2ZPXKjcEJTIC08pbiS6FXPxNt0GyCJ0qdci55
         TO9+AwQc2hG+1wi1NhmXXQo2ENo7Hp/4Q/eHhcZ1P8vaG5tvXSCt5iN95R1dxiPnXPmY
         Mp9u9SgsKkhRVjw3B4Z+bp8xD4UomAYWX4bYlv3GaIOsPGblMhz3pbfieCaDAdgQnpyT
         akwEPFK9TDkupyIyTwASz2bcb+vApjDZDO4kDr06bMmqmVt1DXaloTa2y2MYXSk3ByQZ
         pD4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hiesufd9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iefNICkzamusZsp8DrERyGtfggk3tJ0fgyIO8QlUG9Y=;
        b=bUsD+ZNYTLUifhsTM1iGz9/mp3Nz8IMH3LakmlMWPLcNQDoFqa6Yv7nu1n+GIw22t5
         tBBHyw38FA7M4VMyw9ICLNkgUNjQ4AvPM/TmljzO1QbTiQhG9PRCzQlrGXPQ06Fw0fwA
         IXmBDvvEtLlJGVeqb7JhAfNU/L0LTiTN4FqSjUvmyBFyXIVP9QTnxHlyXm6OBzjWz6hV
         pkYPOnfzKuBWqWuvGL/4ErccMx9MpzZVNftputIGS8eTTfKNv/ZhjrRCYMlS93WNZ6bG
         Kpkj0i1kG0WWe2DgO0yAawY8civPhwdyRFBEfE4iZQqPk6PteHLEpI8hQC0rm9tP3oOP
         vPTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iefNICkzamusZsp8DrERyGtfggk3tJ0fgyIO8QlUG9Y=;
        b=hM8XV3T4MkhFp+Di0AXWRCWrhQfJjYggIwG+I18kTEAQMf3hA2GV+M4KV6OAllETF/
         xQNjXTviBKoph606fZ5+pYhGjIf151GS7z4cBXGi3hVnx5CyOc0ferFaqudV2ELsuy/D
         TQ7s6jVjI7aS34/fdpU5poy0GiNHLbAPPpE2HIy+gz8iqskx6oQJL3pD7cfcxJVw/M2u
         F3uXi2LmstW73N7Rzc13TPmLDozHfDGMt8LwRqxTMDc/EGMazIHoQS7F6CKnKk9eaDlo
         kM5k72EVk7qt5xrj34yzD5ANj7y8lJm9YGDHIopY3CtPxScI6PUIRxYnHa1EENCloM88
         zy/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSGtqjfTJjPH/crdmJ50agVLfEq/FdxUA/qPXe4CQTWG+0tQf/
	VuYyuFz/EWmonN0lpx62PhQ=
X-Google-Smtp-Source: APXvYqzG94nXPFiYS6idxevzIHeSX2qPYdA5phickvAuEGPF4xrBfhYsNe8B4mniRwdbSukoWgw6/w==
X-Received: by 2002:a17:902:bf47:: with SMTP id u7mr21786846pls.77.1567607828477;
        Wed, 04 Sep 2019 07:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1c24:: with SMTP id c36ls4788201pgc.14.gmail; Wed, 04
 Sep 2019 07:37:08 -0700 (PDT)
X-Received: by 2002:a63:d64f:: with SMTP id d15mr20129130pgj.345.1567607827977;
        Wed, 04 Sep 2019 07:37:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567607827; cv=none;
        d=google.com; s=arc-20160816;
        b=QtSXx+FQu0rcfq8+NX6Hsl92aes+dB7ZrzDIwnx+DxQ8uKlRW0RlHGDj/vRo6hPLT9
         U5aPNlFEv7RrBBYTcJqjnimsxWZAkVN8ukcNYdCWC3n3DP+dD99SrODdUW2AbSic5atS
         MgU6jAPPe7/A2086u1vUreGuZWv250aJin14AdBUk/ouRyk8xUPg2ym1YondRiyx0wQX
         1LHE7hAOiWLwgPiwxRz8G6WynKunKpFHwq2AcGvfJyjL2KIyA+v9kcMzNKA1lk4n4R9n
         7UAyr/drQQ+duIVgScd0l4uU/PEGO+2zTvRvo5wi1zpPvMC3gWoKwZWoYYPbFnu6eeFI
         l1ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=d0VTPW60ciEzDbSTuQuRbRvDT6v3yNxk5P0Eu/d/VEY=;
        b=gLeOuniMBKKcGnKTRcEuhzKtQzVI1ypP3b+a46HspsWO4SkwQnvlQU7c1j3oRYkfdR
         Uoti7sobNe758Ec6714gVdb9JNR5MhryuaDxAOhywIjmgx3EjABst3krueWfEVj4mphg
         ew3PfVmcKHsKKrE+wyr/oxEqWvAVqU9Na9elBL+/icvheU3sZypl4ud2J1r3l3QCmj/U
         orcR9gawNmE60JEWI7TRP1RRCl9JC8iThGjEw80/QZh3WPzSSeYuujFIpidFo+b/ngq+
         yBGKdLlpjdGSmF1+dDyGXpJcGhNAXEf1DdTm5L9e+CMA0D+sIizpZ9J5lDpXyY1VnTVi
         K5/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hiesufd9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id w7si171975plz.4.2019.09.04.07.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2019 07:37:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id r15so18970502qtn.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2019 07:37:07 -0700 (PDT)
X-Received: by 2002:a0c:c15d:: with SMTP id i29mr18468496qvh.5.1567607826937;
        Wed, 04 Sep 2019 07:37:06 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id x5sm4919859qkn.102.2019.09.04.07.37.05
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Sep 2019 07:37:06 -0700 (PDT)
Message-ID: <1567607824.5576.77.camel@lca.pw>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Qian Cai <cai@lca.pw>
To: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Konovalov
	 <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Martin
 Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 kasan-dev <kasan-dev@googlegroups.com>,  Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org,
  wsd_upstream@mediatek.com
Date: Wed, 04 Sep 2019 10:37:04 -0400
In-Reply-To: <1567606591.32522.21.camel@mtksdccf07>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <CAAeHK+wyvLF8=DdEczHLzNXuP+oC0CEhoPmp_LHSKVNyAiRGLQ@mail.gmail.com>
	 <1567606591.32522.21.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=hiesufd9;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Wed, 2019-09-04 at 22:16 +0800, Walter Wu wrote:
> On Wed, 2019-09-04 at 15:44 +0200, Andrey Konovalov wrote:
> > On Wed, Sep 4, 2019 at 8:51 AM Walter Wu <walter-zh.wu@mediatek.com> wr=
ote:
> > > +config KASAN_DUMP_PAGE
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bool "Dump the page last s=
tack information"
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0depends on KASAN && PAGE_O=
WNER
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0help
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0By default, KA=
SAN doesn't record alloc/free stack for page
> > > allocator.
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0It is difficul=
t to fix up page use-after-free issue.
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0This feature d=
epends on page owner to record the last stack of
> > > page.
> > > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0It is very hel=
pful for solving the page use-after-free or out-
> > > of-bound.
> >=20
> > I'm not sure if we need a separate config for this. Is there any
> > reason to not have this enabled by default?
>=20
> PAGE_OWNER need some memory usage, it is not allowed to enable by
> default in low RAM device. so I create new feature option and the person
> who wants to use it to enable it.

Or you can try to look into reducing the memory footprint of PAGE_OWNER to =
fit
your needs. It does not always need to be that way.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1567607824.5576.77.camel%40lca.pw.
