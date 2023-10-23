Return-Path: <kasan-dev+bncBDW2JDUY5AORBMNZ3KUQMGQE2T4PLFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B275C7D3C1E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:17:55 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-27d1aee59f7sf2829346a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:17:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077874; cv=pass;
        d=google.com; s=arc-20160816;
        b=d7i+Vb6MkE+BvXHzEHbEDS/dd4ZCbrpuXoDxLqRSI80Z7/e8n6YCEbmYUgV3QtKg64
         z64k/NktxfyP/zya7Tmwgy8s9tTNyERPYlNJ463r8Yix6+oJJukAECquyJokresX5our
         v4aIwespG5Wv2sGOhYPX3quP7cLw5Ys0358Q7nHurLF0YCS8t660vbZbAHvNrzdAI2DZ
         Gu69ShmzMLkbT/BqHP7wj0RP4gYyqn4NvjTyloom/IJql0IESBD1Xyzz7kXKWH5jeX2o
         Efknr6v/uiqSOUlPI/j6VzIxpGSgkMAn4/PgOBmnqIZsevxO/+wVwyWVeuFbdfiuCCZq
         lVWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7vJCOnO635sc6NyE68t+gGIM5Bvkc3txDwJ/4U/Wi3Y=;
        fh=UYz06EvMPMvknpMxEJVU33G5dgC6Oatp34wTBqbMcro=;
        b=j9oueb6zQriwPPfWEOFy1RzVRPtC/qdjEBft05l7/ZAJycZ4en3uQFWLar5moN27Tr
         A4ii9OUk7uU+P6xzmQq1CaoCkNiCDIUxB5T305hyPBeVhxzpFkdJ3s4HW8D2vSDeSlzS
         DEW+HoUvRr5CUaQfgmU4p5VYtA019VOx55mHx8/3wXcuCEHBJ+7sHflBp51NFCj5A0A4
         DN5smIUu1gmiv69fJF6oZu2pDhsL6HScX8HuCojv9+GKrbl9sqlR8C6dAkJFPCrdXI72
         phJ5c6EhG2TxUhPQ5T6N9rTYhdy29cB5ERG2915a6PxlT085i984/DsjI6rn/vjfvL5Q
         /B7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SgUD8rug;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077874; x=1698682674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7vJCOnO635sc6NyE68t+gGIM5Bvkc3txDwJ/4U/Wi3Y=;
        b=cx2zeOczsM0XugUdBFj0yAyvjFs/RYvv8+fXiZi7QCXQB/afJpsw2OldI6yKnNzCC0
         jcmfKLr02tsCmDjSTrfmXdrXfcrUuxWyP2mrC25Ub22FJzERQvrlPcHRH2K3+ddE9kw1
         sDG6KO5fkkecOHUmpMLeyGpDgjLyJA1DmnN5OT/NHOf8viTJm0Q9ErLcH2Dm/fcWnchR
         AGO3xC82Tmj2DfPZohaSDKM97tycLACHxNvLIzs4wrUZ7G3G6TRqCNdf2cnlPiPKZC3+
         zStcxF9alCeKqLwx88jMF47r2X0vDOOfKvcxuGPqmpypSvpt0IkChADSmIrPUEDiz1oc
         K7Aw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077874; x=1698682674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7vJCOnO635sc6NyE68t+gGIM5Bvkc3txDwJ/4U/Wi3Y=;
        b=F5oaxEdxpDDZhl/ufXM5LNc9t0DH6unmLO73OSicPXVjmuP9QGYuQ4u/GXb0xhi0uT
         DSVWw7kcNsLXNK9F+6xz+8ePGgp9gOejAJLiCvfkKap6RixTHsDgTW7fClL1U2lDsCi6
         5ZTskztR6JPRi6E2ahBOful0ymtB+KKjxkw7g8KtjIzQM5h/stfTB67AMjc7RN292QMd
         e277jf/mu4UkOZ1wlCGGBrDahBKgjPU0cEYFH31LnXT8u7OzBBesxMIo06NzefvfpCld
         Cw3PIp6D1Y1oXlDmPYqtwsR5XtZnnePSJ1QJ0fA4Cvmfq97490hGlt+Gq2wD0mo8SRMQ
         5xvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077874; x=1698682674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7vJCOnO635sc6NyE68t+gGIM5Bvkc3txDwJ/4U/Wi3Y=;
        b=YrZQh8nUu6d7lq08LNeNhDMmZV0h7pFn/r731qvW4nMVYYtAXD7cOn/5PRbpEZHs5Q
         cXI0iBK3en1iQPocawxLfhXbITfdB3Of9TWuQ/xy1Egdm1KwX7mjiZIvnyFvulhVKJ4D
         8QkNRE3/eWruzMYD2sWHbrL1+BvBawxhYJOaMxyaq/E5Y1t2RO9RO/H1FQXY6OAI8g72
         MmdvkujTBoPAtfTi43X0nirtmWE6AfCvZLZ7FJLOgYfbah0k3XfM8KoZtsGH9v0BBZhg
         z/R3WqfUTTik3e5UcTh5ZzGsuxoKzOi3ozF2s7kn/3XMYef6mzkHKqemrF55Vi/x2ZKf
         Tb7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwzPiPjLX0h13O2TRP+oPncWPvUTzsmAI2By8Ley3EKUUYImNB8
	hD1m8H2H4ohP2BgQo3Gy0XE=
X-Google-Smtp-Source: AGHT+IGnGH+Iozkvqklmi6ZlPN4lIAPIddmdlDvOftGdOCYwnUmIS1tosFr9p8g9HCFEPiDxF4x6qg==
X-Received: by 2002:a17:90b:3949:b0:27c:ef18:d270 with SMTP id oe9-20020a17090b394900b0027cef18d270mr6649510pjb.20.1698077873749;
        Mon, 23 Oct 2023 09:17:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a47:b0:277:53c4:5694 with SMTP id
 lb7-20020a17090b4a4700b0027753c45694ls453465pjb.2.-pod-prod-09-us; Mon, 23
 Oct 2023 09:17:53 -0700 (PDT)
X-Received: by 2002:a17:90b:4fc2:b0:27d:661f:59b8 with SMTP id qa2-20020a17090b4fc200b0027d661f59b8mr6324607pjb.3.1698077872793;
        Mon, 23 Oct 2023 09:17:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077872; cv=none;
        d=google.com; s=arc-20160816;
        b=FFKjIcTWyUtTbk2nlF5VY3SmAgBeIvAF0JvLGkImozJHLWsuUgyQ7B1aYIXCLgLCYF
         VBaiGI10FgKy5HmE0zNVirw+cLR0ngLgM0NgxF5Int2flCGa2VRNnbLK3aTZaJF8pZdL
         qp7zWFeliGd4K4BpKNiW2+MqVrUs0TTStvPVm0bbSHVRWIorJMq/oJd0MY4k9n18S837
         hKC8Te/nRBxGOAI19YtelIg1Br6VpBuEKWoFj8NPQSGBtjT0RHeX6T6h4pHGrZElF/ue
         xRY+BTrpysVrHB9iIuDe5s3tETeoOOtpKbI/+B/mSO5Antye1s634kyLRj+cwhjl4vLN
         fA/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6yATWwHsptne51eJuPF88jokz2oPp7uVzj/nBvs3wVg=;
        fh=UYz06EvMPMvknpMxEJVU33G5dgC6Oatp34wTBqbMcro=;
        b=zgJaAZqCeEDM/ElYm/+M1jhvJ21FDY9GLD/uH9MdtDX2ZH1q10N4lYHoqm/tA+RAyV
         p3JjFgk+Ob8ZUM7v5jkqMy8K1HpHUaw5YKVXC7Q5MzUeD6rtOVGo3gQc0h9rBdfo0Onz
         e21I/8lh5ClXYxY/FSULN4hmoV5HrQWRn44VDWcoVck7JiAXDV2AhStrb9XSmMMf5zSJ
         k0989SpC66FRpHnm+e1DGvLV2JvueCLCJPU1WgeSblysgmyKbMb4E6WNlIqoUy9Nu04+
         mQumwr69SDFoVMXUsAyGzJLk9OJj3QTaWZHbHM5IaDKMRE3YfGT+UJFPNHTlF2haNEXr
         YoXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SgUD8rug;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id sr13-20020a17090b4e8d00b002765f40a121si427304pjb.1.2023.10.23.09.17.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:17:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-5ac865d1358so1969290a12.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:17:52 -0700 (PDT)
X-Received: by 2002:a17:90a:19c5:b0:27d:e73:3077 with SMTP id
 5-20020a17090a19c500b0027d0e733077mr7197699pjj.1.1698077872354; Mon, 23 Oct
 2023 09:17:52 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
 <20230916174334.GA1030024@mutt> <20230916130412.bdd04e5344f80af583332e9d@linux-foundation.org>
 <CAG_fn=W0OO4GGS0-pnHFpnWGsBN3dZJ9tnRxPmEKRkkP4Vh48A@mail.gmail.com>
In-Reply-To: <CAG_fn=W0OO4GGS0-pnHFpnWGsBN3dZJ9tnRxPmEKRkkP4Vh48A@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:17:40 +0200
Message-ID: <CA+fCnZfRh=a1VQx7CaHAjTQw9888jxFHB0dJv5hkBW6v3njdkQ@mail.gmail.com>
Subject: Re: [PATCH v2 12/19] lib/stackdepot: use list_head for stack record links
To: Alexander Potapenko <glider@google.com>, Anders Roxell <anders.roxell@linaro.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, andrey.konovalov@linux.dev, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Oscar Salvador <osalvador@suse.de>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, arnd@arndb.de, sfr@canb.auug.org.au
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SgUD8rug;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::533
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

On Mon, Oct 9, 2023 at 2:16=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Sat, Sep 16, 2023 at 10:04=E2=80=AFPM Andrew Morton
> <akpm@linux-foundation.org> wrote:
> >
> > On Sat, 16 Sep 2023 19:43:35 +0200 Anders Roxell <anders.roxell@linaro.=
org> wrote:
> >
> > > On 2023-09-13 19:14, andrey.konovalov@linux.dev wrote:
> > > > From: Andrey Konovalov <andreyknvl@google.com>
> > > >
> > > > Switch stack_record to use list_head for links in the hash table
> > > > and in the freelist.
> > > >
> > > > This will allow removing entries from the hash table buckets.
> > > >
> > > > This is preparatory patch for implementing the eviction of stack re=
cords
> > > > from the stack depot.
> > > >
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > >
> > >
> > > Building on an arm64 kernel from linux-next tag next-20230915, and bo=
ot
> > > that in QEMU. I see the following kernel panic.
> > >
> > > ...
> > >
> > > The full log can be found [1] and the .config file [2]. I bisected do=
wn
> > > to this commit, see the bisect log [3].
>
> I am also seeing similar crashes on an x86 KMSAN build.
>
> They are happening when in the following code:
>
>         list_for_each(pos, bucket) {
>                 found =3D list_entry(pos, struct stack_record, list);
>                 if (found->hash =3D=3D hash &&
>                     found->size =3D=3D size &&
>                     !stackdepot_memcmp(entries, found->entries, size))
>                         return found;
>         }
>
> `found` is NULL
>
> @Andrey, could you please take a look?

Found a bug, will fix in v3. Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfRh%3Da1VQx7CaHAjTQw9888jxFHB0dJv5hkBW6v3njdkQ%40mail.gm=
ail.com.
