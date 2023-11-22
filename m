Return-Path: <kasan-dev+bncBDW2JDUY5AORBCEW7KVAMGQEW3C6T3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D11107F5456
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 00:13:13 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1f5acba887bsf397207fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 15:13:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700694792; cv=pass;
        d=google.com; s=arc-20160816;
        b=ngyjDVAW3rKlALR+aTqy3TJKZR+Q3IYlY4G/jS3JX9MIvLJ3uC1bemx/SXg5qv8jVz
         ycd2Olznp7FAeFYBtU6PNok+qRS5E/kMfGYgPvS2fSGlBBrk/trnKyH2mE1BRtvF79wP
         lYK66vG3sxnAyg62nyaUMucRypmV78RutaoZCRFLqSMmkH/+RsOds8ogk2g78ljeIuaz
         90SQoc16vtoVgRw7Maogh6clu3iFUhRNAy+BssfvnF1le3Q5Md4loGrW2tpRBGcwMvBv
         Cmv5XXIEn8GiVViJaeuSzf67ntFJiVvssUH2u7XYzCM+YdyUVTo08QQaW4B61f2zWXRf
         8jdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WpxjDCziWMx3zUallQJEqptfFZIEKRsI9T5CKf/ClBU=;
        fh=NCHtEozBmskezwQJYaDd8FyKLYTfvS+9oxv91JlPuYk=;
        b=x/mb7edIeCfOUR05zEhng4wYWh+BaTl7hHlGtABdG4hk/2ujBc7aUAFjVyw5YuanHY
         GQlM3E65aKJeYYVQty8d/Gz/Nx8gCqLG5IDoOzd9Iav8jEMAIhYOKXUDsuqX27jnMocr
         lYuhWCpp2lOj/cWchj1irpNiLjhG5w+bQAU68cqrFBI2hQ+hMzHQ/SgCu2+dxwF7yaXI
         LBpnSc16QDxDXMuf55MteOik+iNMuQklHkosHEkQqwf2/rrk20weg+805E88TaFNDHis
         62eYSyFB5fFhSthik9bTADot7oHCf0j3csunvm7SR0swdt6oSGQxi1JanIyY58snmfHn
         OI0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HAOeLpyH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700694792; x=1701299592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WpxjDCziWMx3zUallQJEqptfFZIEKRsI9T5CKf/ClBU=;
        b=MnY3092P6ec5LczzvHZb9YNeTcJqX3ff5PB7s1bBkakAwsDQqmQrvPG1i2a2vaqUuo
         EYx9lbKTfqf2qPxCykEey12884xNC/L4ptPirEq67KH0BhE3AsNNs+NmlF6LV/Y1+0l3
         FzWQcMWk+Bj4lXvGGIbgiDhT9eB4KbF8EUHhdXB29GacDDkZhDVr/j2H/X2SSEJTk21g
         M/PTByUGEY+xmwSm/PcVOqE+jG9gDWxtxJ3DHQzF/qZc3sO3HcHt7dASnfM9EFogHYVm
         r3rmDPl7Dw2oArBuHABgxyDlolZN3Y0r7u62DPBBziczEvs6HPHpeFB7THZgzUCk4Wjc
         RIzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700694792; x=1701299592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WpxjDCziWMx3zUallQJEqptfFZIEKRsI9T5CKf/ClBU=;
        b=kCMyuqgrffcQX8CytD4Toi+LnNYtZCHwzvLzxPimXyTq7vsJPCCt+YxvZppeLKK8nu
         I6TkuxlkVebamn0q5+PpzF1LubbuBKLGQqN9XlwVj3dVU2AbhJsjFqUOujptmwalp924
         +gb8DvBqHi2FyE1EmXeBIckzgUIcaIuRrOkBOolkQNPQgG5Bf2PNonVUwHJwxy7II44p
         /zp+GIh85XaMHG5ltVqrCf9iuxedR5K47AOlpKAXFOo+5MMkUMhmViRBcAJiZFiDN9zL
         e8jBW4uW1wlXB+bKA5dylu/vntzuRGQv7IlMxPza2UW3hJiqphNCm8oU3PNJvk5UoKWs
         /7/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700694792; x=1701299592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WpxjDCziWMx3zUallQJEqptfFZIEKRsI9T5CKf/ClBU=;
        b=fBRkecq+J1M0g0BXIiy0ks6w/lkhEaLbi+gmcfBb06zrL/2EdJ4mR0cDdom2V5QtPR
         a0zhTtnJLsQXwSLu5S7IfJrY50UkKPlviAWfQJ3UJkfJPFkkLhkJccJE4Tl6Q+OfD5hR
         PC5zApboHPietP1BMHUPSRiLkoEQP9EHL+uPo8QoHeBITpG3AY0cy0o/3jy79jiul6PF
         +R+Wbx1MmGXYQyTZaU0kV+PxzaoLrjoMZ8nhXrHBYj5IjBRYs5bB59sBL3j51s4XQCNq
         m+ODVPT1htWW7G2AESaWat4XhbJ5IiS2kQHr5igr7jwEFEb9bMAse2eGqUjzRJKweKH8
         TIDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwWotANSXT/lWKmPFiz+NIdtJX87jOocI3/isPE5LsigEg8n4jf
	TaaCmHymGHRBKXlYojoDdMg=
X-Google-Smtp-Source: AGHT+IHSqfADvQJBNz4W3AiUdJGdQ+a6bB7spJJF6CbUpwTDkZkMpNZ9iV88epfrhtZ1irz6O83B1Q==
X-Received: by 2002:a05:6870:4c01:b0:1e5:89d8:81fb with SMTP id pk1-20020a0568704c0100b001e589d881fbmr5432784oab.10.1700694792411;
        Wed, 22 Nov 2023 15:13:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b489:b0:1f5:bb3d:98cc with SMTP id
 y9-20020a056870b48900b001f5bb3d98ccls75987oap.0.-pod-prod-04-us; Wed, 22 Nov
 2023 15:13:12 -0800 (PST)
X-Received: by 2002:a05:6870:2b0b:b0:1f9:57df:ce37 with SMTP id ld11-20020a0568702b0b00b001f957dfce37mr5386837oab.33.1700694791844;
        Wed, 22 Nov 2023 15:13:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700694791; cv=none;
        d=google.com; s=arc-20160816;
        b=IanYXATdReazEfefYQd5u2ETGdOXAuAMvPZnieEkHXaUs/QCSkBp8i5ZXUP0Dy83QN
         3wrInZScX/A1RVRlwxAQS8esofVg8oisYlfpSOO2MlkVPIYUy8pHF4hUVbXf/TOmqaQo
         NBlujJZhJG2VjG99RWyeujlpkpXEf4PPeuT9TqHB83VVihNWHP+O13u3WgLK32XnQ6oz
         CXxYY+G/dR0K5vSFRrT3IVkdwnnS2clOs4SQFbALMDlYrRuupd+zvyiVCxAO4DqxMZFR
         ePVqNwWeojnymCADBuS3Dub0zuZ16z1GqIYPX+72Looaf7crm7cpcAaK4HUTo7KvmRti
         eY1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Nwznl9KTGkJM5XPuI3izDsWPQdxM5T7uw0a2p5x8c0w=;
        fh=NCHtEozBmskezwQJYaDd8FyKLYTfvS+9oxv91JlPuYk=;
        b=D9/wIwMXRn8IXZ4SQqYfku65637cach9He5C99r2sCU5QyKxUDLAouadJb6s1P+O8X
         RppTjjE3V2FiWyLylw2xJhBGMYh98CJ/zr71mlUmgWnS0SU62xcWlp1P0pRgZKDxzeiH
         CqBX8rzdRh7HZpubYZohUx+j0iDuPtiEvZ5nf9QgSDo/Z5pqtuBnKtrobpeyqSdZYKLl
         fMVl1wwSffDK+8QnkZb1Tel8CMyzdANMLI1QXwatnXY0N+iM0MVM26j0LeMT/zef768y
         WgNd9vrN3Yarmk3LiFHXRkZnT8V6bFn1co3mS/LXR++6rEpVUTpx1byzJrfdAsUNNSUH
         sb6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HAOeLpyH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id vl7-20020a0568710e8700b001f954907295si9475oab.5.2023.11.22.15.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 15:13:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1cc0d0a0355so2219915ad.3
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 15:13:11 -0800 (PST)
X-Received: by 2002:a17:90b:38c8:b0:280:14ac:a6db with SMTP id
 nn8-20020a17090b38c800b0028014aca6dbmr4019309pjb.18.1700694790978; Wed, 22
 Nov 2023 15:13:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl@google.com>
 <CAB=+i9Q95W+w=-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA@mail.gmail.com>
In-Reply-To: <CAB=+i9Q95W+w=-KC5vexJuqVi60JJ1P8e-_chegiXOUjB7C3DA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 00:13:00 +0100
Message-ID: <CA+fCnZcnL9w=iMgtOqw=bUYRhM2c0MbSbeQUfgzSffqghMutHg@mail.gmail.com>
Subject: Re: [BISECTED] Boot hangs when SLUB_DEBUG_ON=y
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HAOeLpyH;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c
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

On Wed, Nov 22, 2023 at 4:17=E2=80=AFAM Hyeonggon Yoo <42.hyeyoo@gmail.com>=
 wrote:
>
> On Tue, Nov 21, 2023 at 1:08=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Evict alloc/free stack traces from the stack depot for Generic KASAN
> > once they are evicted from the quaratine.
> >
> > For auxiliary stack traces, evict the oldest stack trace once a new one
> > is saved (KASAN only keeps references to the last two).
> >
> > Also evict all saved stack traces on krealloc.
> >
> > To avoid double-evicting and mis-evicting stack traces (in case KASAN's
> > metadata was corrupted), reset KASAN's per-object metadata that stores
> > stack depot handles when the object is initialized and when it's evicte=
d
> > from the quarantine.
> >
> > Note that stack_depot_put is no-op if the handle is 0.
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> I observed boot hangs on a few SLUB configurations.
>
> Having other users of stackdepot might be the cause. After passing
> 'slub_debug=3D-' which disables SLUB debugging, it boots fine.

Hi Hyeonggon,

Just mailed a fix.

Thank you for the report!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcnL9w%3DiMgtOqw%3DbUYRhM2c0MbSbeQUfgzSffqghMutHg%40mail.=
gmail.com.
