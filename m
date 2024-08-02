Return-Path: <kasan-dev+bncBDW2JDUY5AORB46AWW2QMGQEHDNAKKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A7C59465E8
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Aug 2024 00:40:52 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-428072db8fbsf3384505e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 15:40:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722638452; cv=pass;
        d=google.com; s=arc-20240605;
        b=lZ5hTspQ0Dqsa/rTGh3VzN3sEEC4XMjr3iH7nB0rX0qbmJpy9kHkjkxFOnVc4j+4nr
         U1q5NKIUxVujLyEwFHxlsdB9RvLu3wWDIWnczjLF5e2FaeYNyyJGX4hyscylnkFSLLcX
         nFkXdcAdvwcL916NtWdHEXmiOYVFLwcku0ieIKLOI242QVEyxz3PAGuRLjw8eM3uAdAY
         YTpOi8RBKgaotN8Zb+YTooHOYWMVb+v9MbVFfCUl6fru+V78e/ZpXMrZ0JLpPWKSwhYN
         cKcyShZvv39fpaQ1821/oc0K4bfPHvZKIT5Gxdzfbbt07abo6h+/GPK15ZrLDnp9pN4o
         vd/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jLmbwSpd9rgmNLLqSzPlvo4Jt5o9JHjTOWc4a1pCE8Y=;
        fh=RG9S6poyEWSLMmdd74miyLmQ1+Yc1XoXYVFCvBBZnP8=;
        b=GG4+AXNt//inR7ZDfWK29vQdeiRhHpss3IhUrSfFFB452g2UkOIN9odtHmo/GnlMJ7
         AJuCZcfFuWTal+XVqQ2i2GmtKxZIj/pYjdeBpd7zITykq0AIwEpR5s57DgEVYrXkdgWN
         0ebECT+ny+Zph4Vpw/H6gDrIrx9OnGlYZrpyXSlN46h03HBZTCpvua4TpSjqbMFHOVk4
         Mxm5pAF+ltsqYNIVBBY9ANXvMUrUWE5syv+OeD7cQwIAcWfzs0annv8RWsSJLDYvRRRh
         1uloJzpJPEREuH7Nhh0w+oIs1X60Yh/jc1eAUDINBBmoJOVcl71RBvF2DZDcStnoDGoe
         EbRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dfNCou2x;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722638452; x=1723243252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jLmbwSpd9rgmNLLqSzPlvo4Jt5o9JHjTOWc4a1pCE8Y=;
        b=HJm9iZYX2+BXm5O6AJcp5q9zLy6hv/tDGMTzi8KuUTFyo6KVCNdl6qpw3XYv3RjqkB
         /oGIm7nFevMqHJvB6PseuqFWE4ay0JFW6V2Tr2SFzu33Ma19ozkxKFu7NyvGgwcRXiJu
         bzH44XOmfvbwuFA4oWrRR/hamF+sso4W5zCgfMqec4H9yIU0zsx4xPWNy8cN579V5jTO
         x7bYyiu+7ovLZ6bh46lZ3nt1jNLkCuEmDWZqEm1pj5d9BKGRyCnE7Rc4sZVr8neABTwf
         08IvCpwLBAzbgwo/DfQZ+gBNuxqJ2lLskWtuB4ii7jV9vMIQl2YK/MNy2+iWJ7jAOuzN
         koJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722638452; x=1723243252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jLmbwSpd9rgmNLLqSzPlvo4Jt5o9JHjTOWc4a1pCE8Y=;
        b=E2e6T0yhLGHGT5gwUP2xWEOSMoNKbFq8UXVw+9UylxZMWe80VfvzTxPsvZaboH8Q6H
         9yMPA2oUI+HNfyJFMTmk1LH+Oa5lH9AHhlaH2QCs8ssa/Dd/7Qu0NluDwAnFtd76rwie
         uOLH7y/M8xSyH/pwmwe0VPrIgaHA5EpVtTkBDmlvuSb5bXxkRirtJvmXxSuOWVhKNpG5
         qJT6r4kOXkP055N9/fkKahXjh0hAceCNw2CTr01j1Cqz5a4yi30+J7XHIxilB7ndNgVG
         lm2K2LnbFoiweGFpYhXB7IKOI/Tg0FC965UarAzKosMKBfZ+a51re9tfOyEkKNOfhPHP
         aP9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722638452; x=1723243252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jLmbwSpd9rgmNLLqSzPlvo4Jt5o9JHjTOWc4a1pCE8Y=;
        b=eOuNSzoSVavvmJl161YEwlN4ELMXaItfTS8+OJDuDE6Au3PAD7kJtcADy3MrhnqHGK
         Z3lvmRSTg3qex8mcoiQkAftQstkDxVU/BU0/hgdiQp9ff8TaeI3kokjh5yCr4m2JFPdK
         r9R0RHwczZ8vq1fAzIiIN0ZH76nIn7G1u2xZD5Uj0I2FXyuxvyoZj8opFIwSePA39NAk
         eWiZSqt6HTuJd/pQxRGoBrhrScUr8tmze4Z59O+xtXa87gAUUQqPvD6jMJ2taT+SByJ9
         WJ7GZeTbd1wzFk9SjQsH6OtCZZwue3EuqiOKJ8FWig4jBYa8gHW/UcpLWkGyEfsrIyHY
         cPUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXxdy/d1WgGv/x+8oRMj9z0QAXxhEZEs+RVc0fNKiJMZCNqm6eb/gHbWMWVHOKhn0iMpTfBgiRVtpPC5cF7msOrAZWZRtPkuQ==
X-Gm-Message-State: AOJu0Yx1uRVR+yCWxxSeWAIE7ewFuOAGyBGHcOd8YTv61ARJXs/rbaOb
	DdXhJE163i/N87bTEXpdXpKXGwTlwfhvoHa+YHybfqVZpCzq3Nxt
X-Google-Smtp-Source: AGHT+IHknlj+n/iwoDhky2jNqYibR2R39nThtq18RPRnfBzD0tIiVPQNCELK7JG4YBBiBjWgxDSrOg==
X-Received: by 2002:a05:600c:c08:b0:428:e6eb:1340 with SMTP id 5b1f17b1804b1-428ef6d6cf9mr198405e9.4.1722638451265;
        Fri, 02 Aug 2024 15:40:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f0cb:0:b0:368:31b2:9e96 with SMTP id ffacd0b85a97d-36bcc184abbls165096f8f.1.-pod-prod-05-eu;
 Fri, 02 Aug 2024 15:40:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVVOuXmP+kZlNStENO60OdzOsS+RO3UhLGZxyKFNzArPGQhenehcFJ6HrYwINRq2gP2Mxo8xqWMMvnkO78J8H5VaxHuEUTp83EfTQ==
X-Received: by 2002:a05:6000:1c6:b0:364:ee85:e6e4 with SMTP id ffacd0b85a97d-36bbc1c49a3mr3717248f8f.53.1722638449592;
        Fri, 02 Aug 2024 15:40:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722638449; cv=none;
        d=google.com; s=arc-20160816;
        b=ViuKq4/hMzNoNkhkozH8Q1T86SmD3UQeSvtQi54IM8Z9P+XCba+Rtgr0Kv21WXugfI
         G1Hg5cZpu6awPDUN2+tmvMPOcwOe5DUY9YxG3tYDkbfn6zP0CPvDFj4SKLKVjZtVmaqT
         oAMmk+LAfu916NA0Jiz3tJmYoqganywt5hqocyYYVyNsDzvIdM1Iiqe68e88i3V/GLcF
         7+DvmSPvtzUGlV4M99G9OjNZwTs9Wk6sL0BEd5y663jFeAsZPl8Om8/g772nxzZcntFt
         VOFrS6zhcO5ReHofs6VljeKFKYgtu9OuiIW+qdaM9ouR+IygHVdLqjuiYTmLJYw2OOaK
         9F3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/AS4PCqiOdbZ+esYBLs/r2lwVfepCVbyBq4ZGB7mHqg=;
        fh=BhvH13FYgETxQAdCBNbwJhNd6HDnLuB4pDnc/N8Lco0=;
        b=A64WH+zRMJKVwVzKlq1M3CM4pMI2LSDdmO+C1I38c0ABfgigix35p+C5lU/Jt43GWk
         yZxLSMaKKL1IJ75C21PCSW4yNQxDWwXBCu60U2oH88aoukYz7s/YOzrShrNoNMcmTaHm
         5BpsivJ6GfzYekqVUC5Fkaekt8pQzV0rkMlbChoAjSB7ppo3694SY2IMvaUVgu4+oX3c
         divU1LbEPia1vCZk3/ejZm+1DCMUOUGbwKvYURDKFTH9WD0ENNCIiPh+3mUtSoWpS2wc
         76na7bLeoZugSrGMVkFpxifNwdvpb51aVfF7PyDQBM4m3Kr7SHDy5HCad1PQALjsTe4k
         9waQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dfNCou2x;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4282412a934si7758825e9.0.2024.08.02.15.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 15:40:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-367963ea053so5492466f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 15:40:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXj65qnLDMuJmmDyFSOCaIs0tA/+S0wQST/I9PMMJY/HqFYpgr6Lhdh81pneW7KPaXh/pX/a2tB7aqaXs5YNs6tjmRbRMvLUtPpgw==
X-Received: by 2002:adf:fb85:0:b0:367:9903:a91 with SMTP id
 ffacd0b85a97d-36bbc0e0cdemr4158321f8f.11.1722638448698; Fri, 02 Aug 2024
 15:40:48 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com> <CA+fCnZeaphqQvZTdmJ2EFDXx2V26Fut_R1Lt2DmPC0osDL0wyA@mail.gmail.com>
 <CAG48ez0ggtaV8MF-bzzS2=zKg-3nfG1G_QaqGdesAJpQSj39TQ@mail.gmail.com>
In-Reply-To: <CAG48ez0ggtaV8MF-bzzS2=zKg-3nfG1G_QaqGdesAJpQSj39TQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 3 Aug 2024 00:40:37 +0200
Message-ID: <CA+fCnZcZbP-PNG9BZfoOr9UEoqxqLkCviS8ooWOLc4Vp9+XimA@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dfNCou2x;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
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

On Fri, Aug 2, 2024 at 11:35=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> > Ah, notice another thing: this test might fail of someone enables
> > CONFIG_SLUB_RCU_DEBUG with HW_TAGS, right? I think we need another
> > check here.
>
> Why? I realize that HW_TAGS can't detect UAF in a TYPESAFE_BY_RCU slab
> after an object has been reused, but here we do no other allocations,
> so the object should still be free. And the kmalloc_uaf test also
> doesn't check for HW_TAGS.

Ah, right, all should be good, I got myself confused, sorry.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcZbP-PNG9BZfoOr9UEoqxqLkCviS8ooWOLc4Vp9%2BXimA%40mail.gm=
ail.com.
