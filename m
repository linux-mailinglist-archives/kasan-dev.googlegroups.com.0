Return-Path: <kasan-dev+bncBCJYX6FNZ4PBBZFCYXBQMGQEE72D2OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE10B02344
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 20:01:10 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-453817323afsf15197235e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 11:01:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752256870; cv=pass;
        d=google.com; s=arc-20240605;
        b=aOmXGvXNDy0AZT4Noki5s7GeT/luGAAvDBpk4M/rsyeAyQ4dwdPVZQvEYCYd0iKBNm
         Zjd7NEShRPnEahom0/4Igr6LvB8j6f072NvPLn7Z6lfFbd1u3QNi6l75gNDZefHOX26b
         TjXf1wHLC+EleSPxY+PYsiHDOKnRs4QMUDVQjlpqa4GEWUwmKjAZ6rUzAmVCWRg+c5H6
         h/7RKxjrWlqZoPOEXfWDPt2c+LEJ23iW5SOThTExmu/MUgz8oBHyF81QlZpW3s6f5Ibx
         4RoFWlHlVvo6Fr4uIZ4kCbKUH8k6s8srr89ycXsdOtL5Ygruq/ioTA3Id89Z3Ju9p4d5
         4FQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature:dkim-signature;
        bh=qq6ngMW28jDOXOqrkhgK6w58yBXm3g50pXk5IvgUv+o=;
        fh=ZewP6YQMkq0d0TP89u7KbgubMsimqfZ2EoRuL8Hnri0=;
        b=CB+4EFEL0gPivhTRcfkTJ/a//BPPTHz41fVuHcK9R4NZeV7CEKQCYXgzAcoMphjKk0
         ii0h1AxDfuUPAbAZtR9e3X5lfNUGzzLny6deZpjwptzrOs86Ol80tZ3K4kbkwrDFVsGz
         Y8YHX5Dz91HK5zhfNC3pVO8hHBw/CYoT14uoh4P3WEVP1gmnOfvPRH/dRbfyy8LiUyiA
         Mg1KtVEdaa6lbEpRKxyGFuY2K0irBY1EDPTIoBbUxxWRYXziY6U+Sp5afR/jcgRU9Lop
         W065ZkRPCsmxtPy6dJi2AIdW9M/gzL9ODAYyzjhi5sv/f9UbUz4nV+i7s9CbhVnbI5AS
         Dnxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QuCTH5Q7;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752256870; x=1752861670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qq6ngMW28jDOXOqrkhgK6w58yBXm3g50pXk5IvgUv+o=;
        b=MC8ZL3COA6ziZML5FVUOercoQFinRb/YkejvFY9qzBOmdOUB4MWxvsNpkGy4s9Y4Ct
         Gw/KgKii/mRZyy3fuhVA+88xpfrNSz8UTOE1q5vtUobCyd8lP4evt2WNLwi9e0ys28go
         8RVgeU21MygtBlka4Z0FeiX6FnxvCNmQQLfU+o9csYwQT57DFpL7xumdM/bEezJS1dGG
         wAUG6QQNdxwClhTSxLSfTKgeFYK+wGAHqyf2wRPV9lDTl5nu854IpvnFfsykh2h+iPGL
         CylV1mM2X5KxlJ53fw6jEvyWJTjnvwAzB8DdQ3HU+xaEVCoN+jQAn0/xiiAcn5XHTPTv
         HmLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752256870; x=1752861670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qq6ngMW28jDOXOqrkhgK6w58yBXm3g50pXk5IvgUv+o=;
        b=I9NTVXdCrg1jVkoNxdR06YtYHicM0PnGyxMW660QYOogp6+0m1bHxkvFjgf9rNQact
         v83KTfBXmHrYrv/W6zsgxgDNL9qiwlxIw5JYhjL3ih5XB53trwYWLOTpzvWWIVdDxTW0
         cXD8iRBP9uqRRaF0RuEm+VNC8m0Ff5vBNnGx9AxjpPFJ6j+ImgOYGejsCBCON1F6FDSB
         luPctS/uT3NTEfT73jvrywHjjQerwNmsbPYD07H8mx+wY4C0p5kYk9Dn6I1yrs9u/T5F
         KsqyndPrWf8dmQ3UzgKXxUOYgigaJXRBf5uMnO36Z0401Ck1hT3v/qy4kfUGdK5KLDHp
         w33A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752256870; x=1752861670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qq6ngMW28jDOXOqrkhgK6w58yBXm3g50pXk5IvgUv+o=;
        b=b41/M1OjwLFJNdhHA1KECOssFXo++H7JWXaqqbveSSmSx3+7X1WGSaAhO/RHQPE9cd
         mMn60V53ERMntHFpcPdZzbJHknVBqABrjBKN58wdP+fuiw2CdtqusqN1Ka3mLqyB7T2U
         9dN+SymO17cib1+TE1PwSfs0BgCRa4ytUJz6osNWvNcwb4l+qgwBGrT0l0iTE0DxlHmq
         giMIxrCZNkDJ5GCZa71sd8pye5fg/oTS32tb4/SVQK9M6LkT5OIlTpZqG7B74LZbe0cG
         2Vvl4VVbtykvZPIXMB+TWQBV3b/4/IEWzAfYWF+VNwWbKirSES1OMMZ7KF8/HyOZbqnw
         8PJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX03Ve3NSoWPrA3nmGTZCjVoxBomFF80DtW0ugT9grHg7wj3j8GrFQL+KaXnbQqogd+Oxb0lg==@lfdr.de
X-Gm-Message-State: AOJu0YzZo93sAOzU1bZHm02TlfPyZGELwAne5Q/UHnnuLJBkBrNxGB1w
	gxVqGIHtrg1IvesMNycQr0kbuxrEHgI4uZtEsJm5f9AHg0Qd85F5NaYc
X-Google-Smtp-Source: AGHT+IG5Osec4C2dKHdm8ent+IvNiBRbdUJ22YqhvFaQ6Fom8U3iYMYFUaogP9wlUcuFJQkim6TFhA==
X-Received: by 2002:a05:600c:a309:b0:44a:b793:9e4f with SMTP id 5b1f17b1804b1-454f4259cc1mr33793315e9.19.1752256869495;
        Fri, 11 Jul 2025 11:01:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5hbefxWn7WCUw5NMmcI4XCquBK0kt9La4V/3yQNdswQ==
Received: by 2002:a05:600c:8b29:b0:455:f866:3c1c with SMTP id
 5b1f17b1804b1-455f8664085ls2096305e9.1.-pod-prod-04-eu; Fri, 11 Jul 2025
 11:01:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/u+W0Odn4a+o7/oI5mZNbNxQDx6B4A/345xEgTEyzaeF/VheSRGtMbJ/JAl21S94XZ28LHJFqprE=@googlegroups.com
X-Received: by 2002:a05:6000:2310:b0:3b5:e6bf:5d5f with SMTP id ffacd0b85a97d-3b5f1880f89mr3824934f8f.23.1752256866521;
        Fri, 11 Jul 2025 11:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752256866; cv=none;
        d=google.com; s=arc-20240605;
        b=VRCs5X5x0upaaAG6O9mHAk7E+PkRtr9LabMcyVTnC/T1TLAQrF+MFLeaUaGAVZB4pl
         goxbgXi8rwn/i1fYvlmgTsoqb/L3VYGUDIw/e3XaiUy2cclO8iDAZJ2BsvqPns6WrlFg
         fzyRpuWxljEwf3u7rpDnMuoBkUKlqDDWBNgi9BC8NbrkKudr4JSKfl7bHSAWHpu1IyMK
         XONxxBL0DRrulXnBvCagW+mdUczHUlWpODPnyJMVD0USTVurrK0dnhGj4NkXlPUq9z3g
         eqQB7PljjaRlkOgQDO/NBekoIkogwDHd+4HJepEeFPXl1OKck6qT9JhkMnzFZ8c/P/ok
         9cBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=FXNOWT6MTv3Dyhe38G7xRW7KYU7suaaUF5CZ16ccYh4=;
        fh=4f55VDfKHS00OWhx1LhLMM8OIgNbwjQ9JKOCcPE30TE=;
        b=llhXUVRnRtal40ez5qTzFXKMBF8N1sWGKVR0CEWDoUSVeLPxJnLsRNatdT1S66F5wx
         nlLBwtW9NgJHz74EgQNpjfoaYIko03tLjLTfnBWcpSzsdZJH14Cw/Qsjk9h3GY/7P0Qp
         hS6/jhcweGYm8dSpKdJmH1xiwKVusTqbf03XCWbk8qmKfxwnUE95LZd8zldwGStnj2Zg
         7gM6ymZmgG9QKdl3MTEBt84zf+53tv44srtG1OkU6FnMleOD1Vn4nu+Ri9m2hXGZ9XtL
         dh1lTaLkD28uCM25v1x15aTUBLsYk/639dhaL76PcK06tBFXu/chj8K0PbXlyjgoRvk5
         ZOVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QuCTH5Q7;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b5e8e09053si55877f8f.6.2025.07.11.11.01.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 11:01:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-60c6fea6742so4480568a12.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 11:01:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUzl2xc+QbTiKBfxWa075cXqhpUv+otPZjKpD53KwBtFEliSM55ukl8Yf88Bc0sc5GXVs0dOaktuLk=@googlegroups.com
X-Gm-Gg: ASbGncsMFqAFGWgFeM/FvX8cAXo3zGWi5/qcmlnWvtcgXZGw78oA0rQsAqqMo3T3j5I
	PmQCu8ygJs1hQuV24hoDMcN9w6uZG4GgYBTBwrycOjhz+tpRW/8IKNJ/YjSVgSwhwZZnD8XQsv9
	MrfUiOVwjPq134lCHbLl5V+/InuBcY64ZaBFpRs9D+Z+TFLnrayK6/M5ScqI9JgE/DtMlRhTfYq
	Sznjl8S86DAcxkSHLlGz5/WrdKAq+apPb3EQ/tW3QuCyLA1inkiv+HFzT3aJ0zKfNCugZ4EQduP
	KjmpF2J88+2U41GuZuevLY1cyCGEjkQGFqHXL/3cpDXKiOPtZoWq5yGeCILFEhdKqxzcLjJEvm+
	7nfpiRCdj2m2/+sWUL6GLjXkeEMbHoKRahuc6eHUgKFcUPPgpB75RAb0XEmd57/NNDrMpslT3tM
	VDqBdWF4TTUTM0S1WvUwXwH2fs0geCbHIBdmJJb5SEdoU/9lzXeg6mlE86QAKfRi3UIwoin29TZ
	gwpEEVDwsoQ+ORb8n4XdG1ZCFm18gVaJuCSXdz4og==
X-Received: by 2002:a05:6402:40c7:b0:60e:404:a931 with SMTP id 4fb4d7f45d1cf-611e7c0ab1dmr3697521a12.15.1752256864591;
        Fri, 11 Jul 2025 11:01:04 -0700 (PDT)
Received: from 2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at (2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at. [2a02:8388:e6bb:e300:2ae5:f1e1:5796:cbba])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-611c952b753sm2472335a12.31.2025.07.11.11.01.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 11:01:04 -0700 (PDT)
Message-ID: <7deb2ddcf0f3e6cd196b7520ad19e0d2ce07c639.camel@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
From: Martin Uecker <ma.uecker@gmail.com>
To: David Laight <david.laight.linux@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alejandro Colomar
 <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, Kees
 Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>,
 shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, Andrew
 Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry
 Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, Andrew
 Clayton <andrew@digital-domain.net>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>,  Michal Hocko <mhocko@suse.com>, Al Viro
 <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Date: Fri, 11 Jul 2025 20:01:01 +0200
In-Reply-To: <20250711184541.68d770b9@pumpkin>
References: <cover.1751823326.git.alx@kernel.org>
	 <cover.1752182685.git.alx@kernel.org>
	 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
	 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
	 <20250711184541.68d770b9@pumpkin>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.46.4-2
MIME-Version: 1.0
X-Original-Sender: ma.uecker@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QuCTH5Q7;       spf=pass
 (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;       dmarc=pass
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

Am Freitag, dem 11.07.2025 um 18:45 +0100 schrieb David Laight:
> On Fri, 11 Jul 2025 08:05:38 +0200
> Martin Uecker <ma.uecker@gmail.com> wrote:
>=20
> > Am Donnerstag, dem 10.07.2025 um 14:58 -0700 schrieb Linus Torvalds:
> > > On Thu, 10 Jul 2025 at 14:31, Alejandro Colomar <alx@kernel.org> wrot=
e: =20
> > > >=20
> > > > These macros are essentially the same as the 2-argument version of
> > > > strscpy(), but with a formatted string, and returning a pointer to =
the
> > > > terminating '\0' (or NULL, on error). =20
> > >=20
> > > No.
> > >=20
> > > Stop this garbage.
> > >=20
> > > You took my suggestion, and then you messed it up.
> > >=20
> > > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > > argument.
> > >=20
> > > And you did it for no reason I can see. You said that you wanted to
> > > return the end of the resulting string, but the fact is, not a single
> > > user seems to care, and honestly, I think it would be wrong to care.
> > > The size of the result is likely the more useful thing, or you could
> > > even make these 'void' or something.
> > >=20
> > > But instead you made the macro be dangerous to use.
> > >=20
> > > This kind of churn is WRONG. It _looks_ like a cleanup that doesn't
> > > change anything, but then it has subtle bugs that will come and bite
> > > us later because you did things wrong.
> > >=20
> > > I'm NAK'ing all of this. This is BAD. Cleanup patches had better be
> > > fundamentally correct, not introduce broken "helpers" that will make
> > > for really subtle bugs.
> > >=20
> > > Maybe nobody ever ends up having that first argument with a side
> > > effect. MAYBE. It's still very very wrong.
> > >=20
> > >                 Linus =20
> >=20
> > What I am puzzled about is that - if you revise your string APIs -,
> > you do not directly go for a safe abstraction that combines length
> > and pointer and instead keep using these fragile 80s-style string
> > functions and open-coded pointer and size computations that everybody
> > gets wrong all the time.
> >=20
> > String handling could also look like this:
>=20
> What does that actually look like behind all the #defines and generics?
> It it continually doing malloc/free it is pretty much inappropriate
> for a lot of system/kernel code.

The example I linked would allocate behind your back and would clearly
not be useful for the kernel also because it would abort() on
allocation failure (as I pointed out below). =C2=A0

Still, I do not see why similar functions could not work for the
kernel.  The main point is to keep pointer and length together in a
single struct.  But it is certainly more difficult to define APIs
which make sense for the kernel.

I explain a bit how such types work here:

https://uecker.codeberg.page/2025-07-02.html
https://uecker.codeberg.page/2025-07-09.html

Martin
>=20

> >=20
> > https://godbolt.org/z/dqGz9b4sM
> >=20
> > and be completely bounds safe.
> >=20
> > (Note that those function abort() on allocation failure, but this
> > is an unfinished demo and also not for kernel use. Also I need to
> > rewrite this using string views.)
> >=20
> >=20
> > Martin
> >=20
> >=20
> >=20
> >=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
deb2ddcf0f3e6cd196b7520ad19e0d2ce07c639.camel%40gmail.com.
