Return-Path: <kasan-dev+bncBDW2JDUY5AORBMUS32VQMGQEKQUDKRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E00980DE09
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 23:12:04 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-425b4c1b67csf39738881cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 14:12:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702332723; cv=pass;
        d=google.com; s=arc-20160816;
        b=GDDYuhHSzDprSzRRLOp+TYG2uE0DhqAYfcu6pMHIusW/8HbRLDpNuJz6ewzlxmqSh5
         vg6vApFUcva9IQK4I0AzK6ktjEb8P7st8GOJ155WyhFHDvWVW3yQxTVOR3OgtpG5PHs6
         TuhNgMJEvU5wQjY/MBiWGfyrjF5CtEXFXwVtEt0p46ZYFZvxMbdogZnbLupbMGoCG5YP
         FmtvgtWFTQVvg2TwbrIj3W2LjlT+gfwS0GKhM52r9UPyvWtjvWkl6BUhmZ/6jPNkl0Y9
         /NBk339Jo1B9Tuzgdsq8gP203XCXfijfXf227b3+b1DIVXxdzk7NhXeoLisDQf2571k1
         Dttw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=SY5O42fPE6YyOfUBbpsDvxwMdR7wWoiQE7yhXdaMpFY=;
        fh=ADibHOfys6xCMvdJRYGsAbL9u3TxDPeun2r5P3g1MR0=;
        b=IXKmKpq8KnnIOIjMRlP+3t4Eoo3WoB94zzWyjsvMwIgho6NPhyt/KgHSVlZP8qfqA9
         s+dOpHr7dbkNWyAdDsO119wbCXZMboVgOtMg/sf6TnhPE0pNIoK6dO7RcniSPe6zkAIC
         fTxLFBQ3f94bmIWJPgMDPlKzBRRgv20qyxSSKCBalPibfP8GkUSlnBNweLZrDMbgdUmL
         D1pyMpzQP4jsUW2GVBvXY02MTCd2B1pZKrvqDulFNrwh/TFc/R00TaqlznIFY6HLGFR/
         jux/CAYb6z/Ns+LRzg0ORUPaqD7rL31RPdDCTc5uGMwlJ2vNR8z2Wbk2O0tECOvCxoCs
         qoug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bp3t3i7n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702332723; x=1702937523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SY5O42fPE6YyOfUBbpsDvxwMdR7wWoiQE7yhXdaMpFY=;
        b=aks/7gErcy7fGeJuhmVvARBhlyJh8cVEDF1IkyuTjrNHcwVhLI5Qk4wPfNRJhjGekA
         k85gspBblIRxRAKjd3GNb1dHlx33s7s+sCw77lulDDtHUtNScR8G9frpE0YBJx+DMXh1
         xvtM2iFfuYQQO9kFFLIXFKKLWdIYZaelVNeNs1Ug4IIpOifwWGOxZGmuTtQ7x85wFw2U
         tcaMLvoTUET4smv+txiix0ZR+/Y90GOEjC+DlV5+VxgS93EqDn+/25d7p6ybpkqUBAkp
         L5F3hWyWbaCDuo1brvvSnTbxy5x/Mal7BTO0O2PFs7x6Pmz0JBMLwyLYFS4hG82GJV6f
         CXow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702332723; x=1702937523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SY5O42fPE6YyOfUBbpsDvxwMdR7wWoiQE7yhXdaMpFY=;
        b=e3QZJrncVbD+YyDSknaBLOqXoDOBpICp1gc77KlFbHe0+tpcJOn8RWbU3pUXNqyJM3
         E5L5RCOw7qgIhT45lJXH9wZXITq7RZI5npz4yGiFtgv5aYxWx8ki89Co9gRSTEtDLeGr
         6lgRN6wHrTXvPXqOqE0lVJQtJLhs2kAoxFd/OAcUFrN0GyvlFE93oAWLG4mGka56dIRo
         TIl1WAG8TPiVrGghYWnjyMxfcLV3CN1x6uGvnK3aDvXCsBGBSCaw998o3QvcWWsBX1tZ
         2euAkyC9Ty/odxp1TOakFpJZSIgzjkrbPa4TGjlRlp9imh4TBmj8+G04u2K7JmtaasPU
         dQHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702332723; x=1702937523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SY5O42fPE6YyOfUBbpsDvxwMdR7wWoiQE7yhXdaMpFY=;
        b=Mjv040TK9U6nQOVKB49S/OVZkDSBpHPt0ZthKyRmuE1Ky84f6x8yAinR90OTc/Hdx1
         hsMn8O+MjF7Knk/KIl2kQIyNKzFnivoUjROMLfUvjIzCpKkvGJKY5u7BssNxAuRhlynH
         IHJv0omo+D5866R1NUrVnEzoR4o9jwdoxgGjW/tu2+w2MKEDNhmrdfxG0e8+ceJ87V8R
         ff5sZX9FfOpvaBvPcmnhwISlVE/9iMaRWU4X2Jaa3DXMcT9PAxcvNKDknle0Jei2AhYI
         pQLOXiBnuJNDtr+7huCN+KhThAjg3fJRM0NsZONsXCvs0dpPHvJt18uI+in9BDVDy4+m
         oJww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQ00j66QghZVxN4UFzTdD2MS6RMx2FiH/Azvr2mQA29xduUULB
	dISJ+SusEJ/tvaALywout7o=
X-Google-Smtp-Source: AGHT+IGKHcW1sT7WORZH28Ocn1bvaJ1vOHcEgrwNHIVlFi8OSBRYuzqCxIH3dWjKmxcWmGK353bdJw==
X-Received: by 2002:a05:622a:1103:b0:423:a073:8938 with SMTP id e3-20020a05622a110300b00423a0738938mr7949493qty.7.1702332722829;
        Mon, 11 Dec 2023 14:12:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:102:b0:423:8108:893b with SMTP id
 u2-20020a05622a010200b004238108893bls4359349qtw.1.-pod-prod-04-us; Mon, 11
 Dec 2023 14:12:02 -0800 (PST)
X-Received: by 2002:a05:622a:506:b0:41c:baf5:b500 with SMTP id l6-20020a05622a050600b0041cbaf5b500mr7223041qtx.47.1702332722013;
        Mon, 11 Dec 2023 14:12:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702332722; cv=none;
        d=google.com; s=arc-20160816;
        b=WSk6YATslSRm2n6XhxovyfxSfPQvdma8fIbAEUDT/WyGYxsfB7nzKJZ6UWbnSunM6g
         wusBLZzwewgEnsOm7t0Ml/TbLcLSVib5VkR2eMpHLFgATsLPBM5zvda8T7Ytwvg5NnvK
         mYLWCztwbsCYjCzbabe5u4uuSfQ73p9ortK19PwpF8yLuLvaYIiZJxP8LvXXaWGF9CUA
         Cda+jFFU+KU4/upTZr6/bJwfiuRevTzkHEvYFG4ZjMP6qSs74QB4fX+JlDvdOdF7uZXu
         PM5edkhUgYOj2Q6M+IhL14NigCqooGaDgU0fQbyPxponMksj/YmCTNtJxIsYDrzt1rTH
         aHBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DBxEKBNamMvlGFbzwl1mFmti5qczGRc6ilz0oKWYU1E=;
        fh=ADibHOfys6xCMvdJRYGsAbL9u3TxDPeun2r5P3g1MR0=;
        b=mLVQhNrXK8wy5VZNcz0UeebyUbJUbIlW4Er6hnRHeJ/43MTm2hKHRaj7XEzaDcyQgz
         /fGstidWJgJlcH3Zie0wSlPrG7cRJJ1mGQ7RCNKrKVtQ/4Iuk+AfI1KhxODDmBzZYXYJ
         v5SbpL5om2Y0vJHLVktV9vQJ5OmwLi35yyvX51lWwQe2qx7IVOYbjT9dcCt8ocDoNrRZ
         RrLnV8s7nziAHIM4o/YY+R2Fcm85OCnw35hKEZCB75ZpV/fMmWixrBxmQXPoo9U7ai51
         20cTboiLBge4GFo61mmDuunoCC5TxktNNf/iMYUOxP0LQlCkSUG4CxOvVKx4SQh0ux+K
         Qf3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bp3t3i7n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id fz5-20020a05622a5a8500b00423e5a4fb24si1556738qtb.0.2023.12.11.14.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 14:12:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-5c6bd3100fcso2581940a12.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 14:12:01 -0800 (PST)
X-Received: by 2002:a17:90b:2204:b0:286:6cc1:28a with SMTP id
 kw4-20020a17090b220400b002866cc1028amr2291102pjb.85.1702332721019; Mon, 11
 Dec 2023 14:12:01 -0800 (PST)
MIME-Version: 1.0
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz> <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
 <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz> <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
 <CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw@mail.gmail.com>
In-Reply-To: <CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 11 Dec 2023 23:11:50 +0100
Message-ID: <CA+fCnZfhqQ+n0SsZU0RKEov3CkwTNJXM7JTMxtkrODmbJPskDQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
To: Marco Elver <elver@google.com>
Cc: Chengming Zhou <chengming.zhou@linux.dev>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Bp3t3i7n;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a
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

On Wed, Dec 6, 2023 at 3:45=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> The is_kfence_address() implementation tolerates tagged addresses,
> i.e. if it receives a tagged non-kfence address, it will never return
> true.
>
> The KASAN_HW_TAGS patches and KFENCE patches were in development
> concurrently, and at the time there was some conflict resolution that
> happened when both were merged. The
> is_kfence_address(kasan_reset_tag(..)) initially came from [1] but was
> squashed into 2b8305260fb.
>
> [1] https://lore.kernel.org/all/9dc196006921b191d25d10f6e611316db7da2efc.=
1611946152.git.andreyknvl@google.com/
>
> Andrey, do you recall what issue you encountered that needed kasan_reset_=
tag()?

I don't remember at this point, but this could have been just a safety meas=
ure.

If is_kfence_address tolerates tagged addresses, we should be able to
drop these kasan_reset_tag calls.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfhqQ%2Bn0SsZU0RKEov3CkwTNJXM7JTMxtkrODmbJPskDQ%40mail.gm=
ail.com.
