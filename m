Return-Path: <kasan-dev+bncBDK7LR5URMGRBX74VC2QMGQEU4SW4AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 465B394310E
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 15:38:41 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-428076fef5dsf36022995e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 06:38:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722433121; cv=pass;
        d=google.com; s=arc-20160816;
        b=kEis2g1vrTabLvlFaC5BojgjvC0+rlVaEAiLuJcSPGT/gKTK8S73ylfthKqwQbrBk9
         cPgVcxgLhDKCfgcY7CfI4yRkzINOnW2O90fql4nOBelKYUddOMs7SIjuHmBF49ypvJrM
         xy7YAfDICOBNq8nDx7YF8pWvu3tyR9uvcWVKhulo+KIuOdSntxUs421DwK1tBTr7eTuP
         t0Gr6AfuWr1bZcy5pABpcc6uN1hsA+jfEe7XAAikGZLe3K16l95vQ3D1vRrAKpC2C2FT
         /FuPLcPX2IymYvRctx0f5jdJJdmJE2itEY8AP7U7L8e1Rw8uXncniuW8/mNLX281kksr
         6PBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=SmVSXtiTugTR6R0ww7HMCznzmFKLvni8qLjgc4OVZnE=;
        fh=3DE0bbxD2TSK5cs5nbCSJ7GMle3JFLiDVZBFfzPszM8=;
        b=BDIt3FXG5iNUr0E3Tjf07xsvoB24+HQQhKry/tsWQWegwGzTVpqGp/e7wZbUzqFIuv
         akSx02HVuNNxfbPlLeszSzW7L2IdHaHxTdW/rS1aMucE3PxCMi6qGIBh2KeUaop39zgO
         bVptmjkbwOcTtquyNAFqw/6aK3DDXamEi+xOzmyDIICNq0jFMY8U/LqdbPUjuYW3N5RY
         b03/QDu0vfvCVxfu3X9T2vIJjE4SBw6BI0BdxuD46OUQ5vmeg0jhSeW6hiULcVcenpv6
         xpQc7OdlhFscpub93LyICrN+ctSKgp5mKTFlJvYBz1qiO+FBIw0SEkwwpgk1RsNCt1t4
         rKAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MXvTt5Jp;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722433121; x=1723037921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SmVSXtiTugTR6R0ww7HMCznzmFKLvni8qLjgc4OVZnE=;
        b=CG6sTvVEdpO3AyroPEbV2WHG6BorTqwEnazKp67nMy9bMx8UgLfPGVmc4rU/1a4Bal
         ljeXOit2b/Xj+2XzNO3FyihXnAnaLqgPgd0JjGRsPoYBSoylSzpvf7sqkxymoLaQp8nt
         yEcj+VM9h+46E1mLPUo9L4qhX6cKIwXJOnrdinwpWEXJUHAnVUJwk6lt0wO1u3xhgNQ6
         hKbzbat4O3DVt85P55xjL69n7xgLhF6xoQNBe2y8fGkFO/+wYK3/TKzT5BpYsyNBSGdi
         1e4w0uvefFFOVxyQRT6203yN1W3PMOwmQPurkWWaNFE8KoTQeW2efATdGArvd0dlcM0/
         9Iaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722433121; x=1723037921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=SmVSXtiTugTR6R0ww7HMCznzmFKLvni8qLjgc4OVZnE=;
        b=FNVO7th4Waul4dAyw958kWx0mpsW1gYnr1Syq/cNx69pZ9gtf24qT38gpvorxhYprc
         wttNLl7DSIdnmpZPEoHUH7EQNSWJJ2Q5of0IUYJaxZffaMBLIiEccqpT/X1zzWstZoXl
         tfq0lmCwLD2AlXiwvdPYGaARHdM8rBzo1g71kqZiw/mcA/0DClq6I/cVmoq2aWjr5Db9
         3wi4pjj9y5cMNHZCWQGf204nUqpPzoDJFgD/s4vdHnULZTb0W7Vx0UWDt9c3nZektMxQ
         H1rqtnb/05yHclgz00tQrs78CLmAS914+y62iGPa1VV7wrt6B4uSdhljYIxf1I9OhS76
         GPIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722433121; x=1723037921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SmVSXtiTugTR6R0ww7HMCznzmFKLvni8qLjgc4OVZnE=;
        b=Ym1Kk6CUhUjyYrcu5JjAiFhiPk4SJG3SPPfq9tXoVuEY/SpSeEjUfpvjbxm5CwmCwQ
         OvDMmVd7AnkPqQVFX+ucKE+h7kTjkO46b9qxo7sHewwnigfipA5Quku9pKgFhE1ciSga
         GingoulRwJxaPjx6Ph0v2T20rz128ERpJxV97m78J+TjkULQsO90SZWoIA8gAL7LPBce
         VFq6yAB76oVzC9apDJ24cT8UHqUKoqlerpubLiZzRXm5LUUSevL3M+qlK4/NS5tWl8lO
         0dso9itOnGZEMiWMqfMpyorQTrzOEoRQCRY208xA9aUffM2V7Hq0ERmb4kDVHQIMn/nj
         sWyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4glP813CSdX8uiBg5zhC+mOqig2DwMa7M7OWguNz+sNpq/12S+6Ui64LAJ3xBAAo5IJm+lJbn/gq9ky/8XJoxsYe0X8Ip1w==
X-Gm-Message-State: AOJu0YzmbrwqunH02oZq/phv/XBnArBC/0zNZ0qNi9rUIQ1QHV1X2Fzc
	3N/CuX2JQ6uicVHnTkCFu+o1Q3LQoa1Z+WCdLg+F4Ev4CA04azHJ
X-Google-Smtp-Source: AGHT+IFEXw/pHuseeHPHwmoQURzC7Jq0wuI9zmrp1IFaRu/wvGD1SH+1cywxxDHOrp6X6m3hOOm0Lw==
X-Received: by 2002:a05:600c:3153:b0:426:5e91:391e with SMTP id 5b1f17b1804b1-42811dcd2e1mr93322195e9.26.1722433120176;
        Wed, 31 Jul 2024 06:38:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca3:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-4280386beabls31565875e9.0.-pod-prod-02-eu; Wed, 31 Jul 2024
 06:38:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAsQVJ6cJtIrpsOMzYWHoIRrxjOwrMtlrdtliCuN0TQCsMY1Oq7FbUUzuDUoKifHRfH2MM6y3Jq5/ni6smq8UK3Y41nBsacsL0PA==
X-Received: by 2002:adf:ce92:0:b0:367:9d2c:95ea with SMTP id ffacd0b85a97d-36b5d0b7e9amr9136251f8f.56.1722433118421;
        Wed, 31 Jul 2024 06:38:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722433118; cv=none;
        d=google.com; s=arc-20160816;
        b=YpJaEoiHgFhfTipJFJjhZJwYbBGInTpUYNKl9BltSzH63qzIJIyTwGEAQ62qgbeY+d
         tkRfq1+Hd84aT/R/VwuxAAhHnlVi6eJZxvkwnoHi78TA2dkrBSiIfExsKkDkI5AuAYdb
         LqX39QOZBRyNmGm+Gy5yO+yvkPYfzgAGC4/Zz9EnjdDuqnmDP1q18s/vDvGtI2K/kE7Q
         6m+AFu1cnlAlEZgvEAd14DsjZnUiqQzMYwxkMxO6oov2Mdj9WneqEkcXshTfhh5Ng9rO
         LW+orn0dyeETKSj1PT2ZYNgsm+pxMinf/Zr7hEuiOcb6t2alof+pmFW42xhyPRvi2/Jh
         9p7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=mwpnq5JQONtzTfLThmmi+tZ89yGgnZ0Q1ptTZ8E1mOI=;
        fh=YsbUm97HfxCjxJt3GBqxBwC6Zrbsq/Mryiu5PFX2FAM=;
        b=ELopcQrM8nL+IziJPBdUxeOBUHpeTk+Fixepb9ZTGyvqLN14vWQb4pZtVOJztKvWQU
         QakhtZTtb6z7xSOVMUldM/CqlgBkGp7pyhyqZTDmccd0P4vo5rKdDZNwM7JCgwRE8X05
         OdsIxSC2/9BWUYTvxAToL+LUfKLrcjOFxyHhHvpJXkzBtV11zNoKoDvTdkzyfVOIta6j
         wdVIbk9FGfHJ4eKssBftuxuxZjsqmJoeN70jZ35LHYb2WrULVws7BO7yLWO1f8sSrg40
         lZ0sDy6skxmyycNTV9Jbcyd9CJbKelkv5tclqoL0ZCJqA5xGe0LkT14Qq1a83sDZu9x6
         jHbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MXvTt5Jp;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36855dfdsi294565f8f.7.2024.07.31.06.38.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 06:38:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-2f0271b0ae9so70981641fa.1
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 06:38:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfY9gNHKNaFZWIn3A8WSpRXFRNgKDnHz3dmo1HsSpwwV8H6dsyiA0NSTlqhIKrmcl7QxTk6y7GD+idflzOjmKkFXYBUtUtT53Viw==
X-Received: by 2002:a05:6512:48cf:b0:52c:b008:3db8 with SMTP id 2adb3069b0e04-5309b2c2a68mr8829423e87.38.1722433117216;
        Wed, 31 Jul 2024 06:38:37 -0700 (PDT)
Received: from pc636 (host-90-235-1-92.mobileonline.telia.com. [90.235.1.92])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52fd5bd0bf6sm2273906e87.67.2024.07.31.06.38.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Jul 2024 06:38:36 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 31 Jul 2024 15:38:33 +0200
To: Huang Adrian <adrianhuang0701@gmail.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, ahuang12@lenovo.com,
	akpm@linux-foundation.org, andreyknvl@gmail.com, bhe@redhat.com,
	dvyukov@google.com, glider@google.com, hch@infradead.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, sunjw10@lenovo.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-ID: <Zqo-WbpZ9zmYVLA2@pc636>
References: <Zqd9AsI5tWH7AukU@pc636>
 <20240730093630.5603-1-ahuang12@lenovo.com>
 <ZqjQp8NrTYM_ORN1@pc636>
 <CAHKZfL3c2Y91yP6X5+GUDCsN6QAa9L46czzJh+iQ6LhGJcAeqw@mail.gmail.com>
 <ZqkX3mYBPuUf0Gi5@pc636>
 <CAHKZfL1i3D7wgbdLWz3xiK7KkAXAxrsyQjFmFarrM94tJPYh3Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHKZfL1i3D7wgbdLWz3xiK7KkAXAxrsyQjFmFarrM94tJPYh3Q@mail.gmail.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MXvTt5Jp;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 31, 2024 at 08:39:00AM +0800, Huang Adrian wrote:
> On Wed, Jul 31, 2024 at 12:42=E2=80=AFAM Uladzislau Rezki <urezki@gmail.c=
om> wrote:
> > Thank you for posting this! So tasklist_lock is not a problem.
> > I assume you have a full output of lock_stat. Could you please
> > paste it for v6.11-rc1 + KASAN?
>=20
> Full output: https://gist.github.com/AdrianHuang/2c2c97f533ba467ff3278159=
0279ccc9
>=20
I do not see anything obvious. So it means that CSD lock debugging should b=
e done.
But this is another story :)

Thank you for helping!

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zqo-WbpZ9zmYVLA2%40pc636.
