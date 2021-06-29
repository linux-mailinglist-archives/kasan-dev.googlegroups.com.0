Return-Path: <kasan-dev+bncBD63B2HX4EPBBL4N5SDAMGQE5T5A4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E65953B7174
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 13:40:32 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id p19-20020a5d8b930000b02904a03acf5d82sf15910985iol.23
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 04:40:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624966832; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDmchRdZ//isugHu7uLYErH1cyaA5w7O13Bs9KZrzE7htoGjtvmNTVKELb956iOv9+
         jEnr2YFjS6kiEcAnWeJ8Tut7nLkW43jT6lyoJJT7gfdjeMueL6TgN4gr9oL5k5306UI3
         VpgZjt04UDp4QBlbFIqfHDcifp2YzTTWI2JpD8CNIVsEok6OT+DgNdOkgqlcg+0I7r+C
         eDbUQCu90DW5wVUCAVAHhXwIYej9aO8N8IU5Cy5uV3zz0yoFI/Dq6QEH2JAAwn4NS1Yo
         06hQV0rOna2UtNgHInrh3q9SeFdH2Cq38ExnFHMf5oDwlOIZ2lOImnuxcyhG55uOJcit
         T5pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=G+50aGO/0ZveSJDmtcBdFGVm19He93wIzSHOFK2r2zg=;
        b=XC58AiIzJWMZWM4Hsb8BBZbC61debQW9PpTt8hQTsRO9dlZUkd8n6mdonf8TsKNThX
         8EpeXc+cmDxLrDkwiR2+w5ziZwq187XYKLpyKvADmCdDiCiMFb/5e3uZu02l5fAC89zQ
         Aw1ZRBEJu4YAV5w9/pzFmSZ1vso37jAWkiLdyndoShLP7peB8jCJz1jGlvRx7Ld+PmUT
         wOR4ptAcg+DbVbKamNltjETJDa5KuqxXSiVnptDRI125NI6gleDo9hfuHcCKgsIxM3gD
         yn7x3ksMpptzG/ay+mrkCIFbrn9htx9OJ9x0xLUVAfi483VuKrpbuvO1Noi+d0NNS4xv
         GXLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=UfQAcSeV;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+50aGO/0ZveSJDmtcBdFGVm19He93wIzSHOFK2r2zg=;
        b=gq+EhaRtCAGzvKWHVj6ak5mbu4PBeb0ToHS1R6Uv1w6XtcaAHqPGVAe9HxOO6CNRa8
         7fdTKOc6aE6NtOG7poJxCcDmGrvKCSygTgvSLmgciI8zas7Sc959ERN8v73kZKPb0Svv
         /sXYQkm60yXcy1IScHnVXbjiZTQmktZQwRclGohrTqniCOzcrmHF1qcw9vH1svWQJ5sf
         shxi4BQz2+QmVfXe0x10AE3IIXGjVEiV2c8J3PyR4mHnLq3J0z1B+cHop3q0M9e62rU0
         0qyJ0L2IRk2QPjmx/hUGxA5ALZ1SHRy+uGob+Gi3R1pNruYGqsiGdW24JCPOeLqYhdH+
         jmnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G+50aGO/0ZveSJDmtcBdFGVm19He93wIzSHOFK2r2zg=;
        b=OkbOovZfVOy1bEJBaqfCZVrG4+RmKw2f6pY4LzvyNNR9KtLXAf0s2CFiGWXL5R+Hlm
         vihZxw6TqL3O7MVLIEKInH7SUARno677GK4IaxnyASgBXWTA73vqlu+p0OP43YqwW24+
         qcZ9xUeFrKN748LNzCoNdpHeK3vV0Z5WockRi97qzSD8FG+1KSDZqQAMa/vfRN5yCV8c
         PXzZDCdTjPql2519hXJJnoUMZn67qQ2LqUg6QFwGWAnW8CNaUtA2ETcfAmBSNJ3647uu
         0PQ9jfS/a6pVA1/hIQ3Iu07M2in++cb9NlGJOXFHN6kS0JRumAz09C+3/jb7HzQXZoXc
         pDlw==
X-Gm-Message-State: AOAM530hARQRYE7aUC2vuFDzmbsEaTtbkOO3V24s1AzZLuPY5QZZ1WVr
	iMmICQxED39zDafjXJo59b8=
X-Google-Smtp-Source: ABdhPJxVDHv0lRJa1c0VHxs/SiRUboMDXA04cHvHQeq/uOy+3ibnIRhrlJ+jyxDW6xEBC+yY/q3YKw==
X-Received: by 2002:a05:6638:43:: with SMTP id a3mr3893499jap.41.1624966831887;
        Tue, 29 Jun 2021 04:40:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d4c6:: with SMTP id o6ls1965297ilm.11.gmail; Tue, 29 Jun
 2021 04:40:31 -0700 (PDT)
X-Received: by 2002:a92:cbc8:: with SMTP id s8mr20522943ilq.193.1624966831573;
        Tue, 29 Jun 2021 04:40:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624966831; cv=none;
        d=google.com; s=arc-20160816;
        b=JUPZfkv9od65YPVC+g2xgvNQZFgV9v9n0eWfDTBncKdpX1YMdFvOqMzAbBjuNU2pOy
         D+8dJKg6bTkuu1iOOvMPAfqKwS8NsGvT9acS4vdt//xlhMG9LJ86AhDZ7pCfWos5mkx9
         My+cDQckonFGyD6N1+QwnK86QTY+whpmWgut4iBwcWFaFHOGk4LSOaYrC2+pi3HQxMvz
         tTb5bwt7CL66TsLFAbPxFce7unbpOmcHRY0hFo8bGne7Ra2HKKJmqc0cIv8YfQ+oMyfS
         J/JWf6Wdzq1bW3D0gDkcc5uTVfIsEESDdGXgIMtfFKRlwCqh9DCDwb3MG40QKfx37YOz
         54XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=cY85RduMbCPMd8R5fgtQlYocUrJ+UgRnlC7mI3SHP7k=;
        b=m9OCLyrWrW211/dIP85HYBKS9AouJU3+haNvziQnT+KWedtGUPx5kDzPgaSTvxBttL
         2nUvmBBeU6BLb53gvZMsId2pWt9KZ2hoEfmDXqyCMLgjJjMgHY4tNP2Xw1v3hCngzFZD
         pC0/LDHker6RYtE0+LGU/PH3dXb+Rvou/a90LwjI+T+dHiUqVnw9etwZc5gUWOUbJYp8
         Tkt26Gb4n1A7aFf+IkIJu9PfY9D3yguq2s+wbnmOHbfctKHZikiKrkhDkaUr4jypq9k3
         PDfW+QB3TYjn9RNu0B7rSA/GTNMKlSXSb2KFN5bhg5I/Oam9mAn9x6gMIqDLA3lKXkuM
         EYrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=UfQAcSeV;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id j13si603101ila.0.2021.06.29.04.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jun 2021 04:40:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 22-20020a17090a0c16b0290164a5354ad0so1714304pjs.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jun 2021 04:40:31 -0700 (PDT)
X-Received: by 2002:a17:90a:4592:: with SMTP id v18mr33261516pjg.132.1624966830939;
        Tue, 29 Jun 2021 04:40:30 -0700 (PDT)
Received: from cork (dyndsl-085-016-196-171.ewe-ip-backbone.de. [85.16.196.171])
        by smtp.gmail.com with ESMTPSA id m4sm2973019pjv.41.2021.06.29.04.40.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jun 2021 04:40:30 -0700 (PDT)
Date: Tue, 29 Jun 2021 04:40:15 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitriy Vyukov <dvyukov@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Subject: Re: [PATCH] kfence: show cpu and timestamp in alloc/free info
Message-ID: <YNsGnyHJL6i1OZFl@cork>
References: <20210629113323.2354571-1-elver@google.com>
 <CAG_fn=V2H7UX8YQYqsQ08D_xF3VKUMCUkafTMVr-ywtki6S0wA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=V2H7UX8YQYqsQ08D_xF3VKUMCUkafTMVr-ywtki6S0wA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=UfQAcSeV;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102d
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Tue, Jun 29, 2021 at 01:34:27PM +0200, Alexander Potapenko wrote:
> On Tue, Jun 29, 2021 at 1:33 PM Marco Elver <elver@google.com> wrote:
> >
> > Record cpu and timestamp on allocations and frees, and show them in
> > reports. Upon an error, this can help correlate earlier messages in the
> > kernel log via allocation and free timestamps.
> >
> > Suggested-by: Joern Engel <joern@purestorage.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>=20
> Acked-by: Alexander Potapenko <glider@google.com>
Acked-by: Joern Engel <joern@purestorage.com>

J=C3=B6rn

--
Without a major sea change, nothing that is under copyright today will
ever come out from under it and fall into the public domain.
-- Jake Edge

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YNsGnyHJL6i1OZFl%40cork.
