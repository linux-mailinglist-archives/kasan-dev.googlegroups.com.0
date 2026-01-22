Return-Path: <kasan-dev+bncBDW2JDUY5AORB3OTZLFQMGQERR5U4BY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6H8+DvCpcmkGogAAu9opvQ
	(envelope-from <kasan-dev+bncBDW2JDUY5AORB3OTZLFQMGQERR5U4BY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:51:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CCC006E4CD
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:51:27 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-38302f5aba6sf9195601fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 14:51:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769122287; cv=pass;
        d=google.com; s=arc-20240605;
        b=IIzttM8TV8wkr9d7Pvsool4MY8EY3cVSXJ2Qz1aqSfTNA/gr+A9CYC70dsxfJ8HgXe
         IlcE09d7LBWEj/RxzNb4oPSVE1XOIdQuGsk3cfaI/bs+RJKYQZV81MbSSsaoIXE9VSHO
         VfxeComx4+uRRXcu3A50USo5p1uxkOGum8LawpZQXx52sQtGP2u8ucV+jhYGyGGoEhYo
         IHXU5bXXCZLx7D/yeA/yXBW2JT5/Q8Dr+QC7UdbGc82UREhMCi3G65GROzAkHTsD8M8l
         AXoueZOfPNt+MWh4en7TEwrk6+kloNZ06i06H4+nKumwQFW2/YHUi9CL77+EfZq7FPKd
         01qA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WZdqgQmrUO3QRScrVaTkPZeTUK9THya8o3Lv2tVewvI=;
        fh=rcj1iDmYAn9VykPlX3RT2n4RO59ezeDILyAfp9rFLRE=;
        b=SplnswJ3hjVGdbHA/Hj+3nxDj4aNJAWucYa3Kq1AsVE7jyTmAK5gHJxJCc9zO/7+go
         FuCTOz7hPa4ET/MTUefnLWJKDeW1rtV+LQIPiE221HHSeuklbxRKrf1c85DO7hqn63s6
         CcIIkxEsEVmKmvq6nDJFIW8i63ajCgXDlkdGRDysHfE3t8aNhEt7ha/Fiswl06NNk2l3
         u1twEZh4WtDlAEegBBwCEOUFjg7j4MY/lvwjNdzi7NtsDW6hgJ+7EXjtRQGIdr+dojBc
         yYOTOg7jR39ZNfS/oFXGlfBSOniDPdGQnf4EA/TEHyUdlA5TMAEuMdS29v33M74lgWmt
         afnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hYKHC85N;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769122287; x=1769727087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WZdqgQmrUO3QRScrVaTkPZeTUK9THya8o3Lv2tVewvI=;
        b=dWXOM4XTiM3piKrlpgXLbCq8m+MocBgAFebLYALTmm7yv3J31hzNZH0Gpt9VxXQjEn
         oPHj9D/Q3/Jnd1Tl2le3ImTj1QHaTersqGSJVhAjNtDs4IONC9sY1vx9IuIDy5orrRHD
         pufPheq9NJf29R9X6bxyVqwiDIGvoXoAcKZAz8MOcr8dK2Yq+NciCDX97h8f/dYUjxyk
         boJ+NoSu0Ovp6kZLBLrZeSnhgqrQvyzQHa1G14BIifAjyG2HFyIeH7jdj7+EHyp7hu5v
         QXVpopN3LAsJqmZoATbSQiA50wbAZsWhz2GkxId9ZnrAPgcRq6Gf2Y9TmE7Hcxb2ohHw
         64EA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769122287; x=1769727087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WZdqgQmrUO3QRScrVaTkPZeTUK9THya8o3Lv2tVewvI=;
        b=U9lto0ZnO2usByBpPrXucVyGs3xji0KXh87mAveefGl1IYFuBzzqRTGZA2k7KcUr75
         ORtlPdWqU4P6sG8EgSchvFjn9T8WWscWw80qWENqODsPY9UXamm2ePjEr7p9hpYyrR8j
         HD37LNnCDEGvjswIIRmBB6b28RwCsq5tddfQGSYBFpb7750s0IaqfMdd0NVETa59VnlK
         wvnHUqkxG0Og/ZXe/wZi8DYJrSILs2dOG1V4cVE7Pe2PXW2qNJA+130jZ5AQjlpawe3J
         ha6ckTwDwIcRNc1nv/pCE03j8btNPKtWpeNqFzoN+rbmMenAyRr+j1sIM1HT89jKlHuT
         YenA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769122287; x=1769727087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WZdqgQmrUO3QRScrVaTkPZeTUK9THya8o3Lv2tVewvI=;
        b=V2vDw+XHNUF3bM1eyXF4loI77huYfh/ZW8DO3jHvRh4rtk91pB746IBqSSiqwacHTY
         TJeZhJ3BkkveF3gPInx8T+rL72gZqstI4PJbB597dPiCej7caTbpZw8wCqY25ZvFy2jG
         SUAdfmge0xz9o7Jqvz4YfC+sEoCfb5qmqh8oQhix7SQ5UBWnBX+xRiJ/SLzWTV44gm1G
         MTM5vBWMRZ166drdyRUahyRzALa8qQfJwmWMKcib45c0z/QeMJ0pz4vQbRrQik2x59Iu
         3antuTG5ip7lWhvwNQmg6k4Hss84g/rjgC+Zs8ILVmFs+TsMRZxTW36b3XT961UsmFU/
         ugww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVDhtoOuEfLdVU8HjS47nE7rmzLBVrK6BhWU+CGnchLKScbNZB+R7D1t67qW3fX163NfMm8dg==@lfdr.de
X-Gm-Message-State: AOJu0Yx8AAdgMKSBTI659uFq5SK9nLgw7DuPpaE/xrTPn/t/5E70SxBV
	xaZP5AquRtvwYrKqroLTEhc2n5Zs1M4j4ynw+hsIE+jvFFOBmQ1f1irL
X-Received: by 2002:a05:651c:2110:b0:338:10c9:5871 with SMTP id 38308e7fff4ca-385da096e21mr2602161fa.34.1769122286459;
        Thu, 22 Jan 2026 14:51:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GWXmLa8DOT1ZPauwJSgOtYHG8ScA+wCrCcMUK42sl52g=="
Received: by 2002:a05:651c:4410:20b0:382:5b25:632c with SMTP id
 38308e7fff4ca-385c235b422ls1815821fa.0.-pod-prod-07-eu; Thu, 22 Jan 2026
 14:51:23 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWkb+0MWpXrV9tBgQ0UFJVJOJoecst4hTrR8NWxi5DHYL8N1sT6vz9+CsGBQ63/wgfJ5pXZkg+RxvM=@googlegroups.com
X-Received: by 2002:a05:651c:555:b0:385:d067:1c23 with SMTP id 38308e7fff4ca-385da0c2445mr1999671fa.42.1769122283681;
        Thu, 22 Jan 2026 14:51:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769122283; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZDqokzsqZWESy87h9zh83n7Mxwhaf94LG73NMVBGoWXwxIm33Tyqy0leZUi6XqIayf
         xpZ3Jiqi1UjjUEWhWX9+dO1Odp+xDvmD1g+CHhZX6fdYROMc6JW41XnGjUqFKEs4wJxf
         8vxtFTU3UCjrM9VBKa8P/5gqo/rPvuS7Q6R8GiycbTO+IVGdG4o6QtEWBOcsmnix7zpr
         N+3BFaMsmqqRrekvskqxQisEUjA2qe+Cb7sfEpjRnM5BLQd7251yfzLxPYu6Z5FDatV8
         a4cx4WcnDsI2LJVpgqZkHC4iJHXjjxfXJYdOmvVMxteFT7XonATpQThE0FL2CtaFmzF1
         U5Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rFDzRwmjx4EhXlLQDIcJTBz1IG6oyRoOclxZcGUtJtM=;
        fh=qteZoHAXeV4vXBJVZx/hx1Ph0T2NvohZ/0EYcVC8bng=;
        b=a0Vr1OJa+i6v5h4fIQT62sTl/XqT7uGK8FJY4rEmIdkM2KSmR+zEAv36PHgN7sgj0O
         tJ5Vm2qpttRz5HDoRzgv/2Lg1Oxp0gTfJIIq/ZTqERV4NfGno5R/cFusDHXUMnUpYGyL
         3sGdKi8GxJ8ZG0/CThstE7IARKylqi5a93+D3JhZ+egHMEPt9Ztlj8WEdiItl+8exTyJ
         oWXo+aGm0DyrfEFAUfGZHzk0iVNz/exdKc9Bg5aBNd4RG7I+fQSCjHJitRPtLaiENh3g
         OJmvk5xRhTXMf51nw/KnSPl+DHg4HcX1GGk+081nlu4Str1A8zfqmOoF6uaSOaltNUWU
         XmXw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hYKHC85N;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da117b3bsi156001fa.6.2026.01.22.14.51.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Jan 2026 14:51:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-42fb2314eb0so1479486f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 22 Jan 2026 14:51:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769122283; cv=none;
        d=google.com; s=arc-20240605;
        b=R/2HS6M0aNJQwYXIMl0rgmXiyEMZSAY3sXSyBE5K1Qso7uc3TPQEdlDcrNXMgVARSo
         4PCtxvgGRvn4o7G7gdAlWgWNp8dner5qOONkn+NiGB+q1xrYCJCHj1e7wFeS190quEQ4
         5qJZ/J/i1j9OICo9T+KPuNyEGabsF3UUjsn8EiLudurx0SNFUheQ3ah2vnX1CkzThNVb
         jnOdub0fnY1UR70oTHRIwdBdsmtsTnTM8Z9Y+NfJOCU8AFbDrd+cYykdp1jdQcJuS3D8
         y+sDzCiQbN9IkYsJ1I9SZP3G585T6xNE0YlDasHtOuHm6RaJtVEL/XdQjxzBfO1dsGcm
         In1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rFDzRwmjx4EhXlLQDIcJTBz1IG6oyRoOclxZcGUtJtM=;
        fh=qteZoHAXeV4vXBJVZx/hx1Ph0T2NvohZ/0EYcVC8bng=;
        b=ZulTlXdT85MOy5W8UTlHlXCVMpohi6f5mK7POqA+oEDtVGRaZWWVSGLbg6JaNNReMu
         rSSH8n+3PNsYlOsdMq+IEECoypskoR6eey6S4ROfsZiGKgoUgA/7KcY/7QsRat3V8J+v
         wZzRoPiK2URLbTQ2f9Oiz7IjHxF3/MH18Z66ROyYNf1mZpVTfX2BtyRRW2rfsihKBh4M
         fkE0yiuzGxr2mrtapnlv4ILBgVNxtKGWO3bDgAtCmpBQ6AVCPZnuIBufK+lMANKOWI9I
         teHwC+4Gx9MraRem85tlM5LAAFsG+lvGhY8equ4a6omNMnYXUS8FuGQdnfLHqcGdhnfs
         rzMA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCX+KdGjO3yxHKqtKf5XQyuBX/wkElbKnog3W/VZT05JYESqyr8vMCJco9/zyq+FqImXfwOJRmGCwJg=@googlegroups.com
X-Gm-Gg: AZuq6aKdd9hxpndcPkHrkngQAW8wKppSOwHt47vWpkPudaGYAmvsyAvpw2+FMBn8Wgt
	CwC1HAKXjeBK7U7X15waFSJpaKV9n5e0GoewCu6PefwzJbMEVOJARu1oBXmVbLoz6rYEjHg5Miq
	9qJTr/FB3qipIBmSJOgHsQgyKMPOrMm5WsBGm83ZxbNtI3mpeHYsGHIcI51tCLfsoHowPBwXZQu
	rXZ39J3m/hmQQBSCUOe5rMHorVRYAcleVS6VeChftmY+DkbPcHbyCM9vuL50jTZSgJEWFtr8JsW
	yOmtDhFZLhzPfV/6ZThYlyw6c92n1vV8xQQXnG7G
X-Received: by 2002:a05:6000:2384:b0:435:96b7:e0db with SMTP id
 ffacd0b85a97d-435b1594374mr1855311f8f.17.1769122282735; Thu, 22 Jan 2026
 14:51:22 -0800 (PST)
MIME-Version: 1.0
References: <CGME20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718@epcas5p4.samsung.com>
 <20260122041556.341868-1-maninder1.s@samsung.com>
In-Reply-To: <20260122041556.341868-1-maninder1.s@samsung.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 22 Jan 2026 23:51:11 +0100
X-Gm-Features: AZwV_QhMwzaIv31P0NE6po4NpU8l338O_JlbC8ak064KxR_6vqfyzHCQqvW3ngE
Message-ID: <CA+fCnZe+J-G-g594hXZf2G0BMoCuRbe0yM-gsxxQZSymyx8_MQ@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan: remove unnecessary sync argument from start_report()
To: Maninder Singh <maninder1.s@samsung.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hYKHC85N;       arc=pass
 (i=1);       spf=pass (google.com: domain of andreyknvl@gmail.com designates
 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDW2JDUY5AORB3OTZLFQMGQERR5U4BY];
	RCVD_COUNT_THREE(0.00)[4];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,google.com,arm.com,linux-foundation.org,googlegroups.com,kvack.org,vger.kernel.org];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[andreyknvl@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	RCPT_COUNT_SEVEN(0.00)[9];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-lj1-x23d.google.com:helo,mail-lj1-x23d.google.com:rdns,mail.gmail.com:mid,samsung.com:email]
X-Rspamd-Queue-Id: CCC006E4CD
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 5:16=E2=80=AFAM Maninder Singh <maninder1.s@samsung=
.com> wrote:
>
> commit 7ce0ea19d50e ("kasan: switch kunit tests to console tracepoints")
> removed use of sync variable, thus removing that extra argument also.
>
> Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
> ---
>  mm/kasan/report.c | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 62c01b4527eb..27efb78eb32d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -203,7 +203,7 @@ static inline void fail_non_kasan_kunit_test(void) { =
}
>
>  static DEFINE_RAW_SPINLOCK(report_lock);
>
> -static void start_report(unsigned long *flags, bool sync)
> +static void start_report(unsigned long *flags)
>  {
>         fail_non_kasan_kunit_test();
>         /* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
> @@ -543,7 +543,7 @@ void kasan_report_invalid_free(void *ptr, unsigned lo=
ng ip, enum kasan_report_ty
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, true);
> +       start_report(&flags);
>
>         __memset(&info, 0, sizeof(info));
>         info.type =3D type;
> @@ -581,7 +581,7 @@ bool kasan_report(const void *addr, size_t size, bool=
 is_write,
>                 goto out;
>         }
>
> -       start_report(&irq_flags, true);
> +       start_report(&irq_flags);
>
>         __memset(&info, 0, sizeof(info));
>         info.type =3D KASAN_REPORT_ACCESS;
> @@ -615,7 +615,7 @@ void kasan_report_async(void)
>         if (unlikely(!report_enabled()))
>                 return;
>
> -       start_report(&flags, false);
> +       start_report(&flags);
>         pr_err("BUG: KASAN: invalid-access\n");
>         pr_err("Asynchronous fault: no details available\n");
>         pr_err("\n");
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe%2BJ-G-g594hXZf2G0BMoCuRbe0yM-gsxxQZSymyx8_MQ%40mail.gmail.com.
