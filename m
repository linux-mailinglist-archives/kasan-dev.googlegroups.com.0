Return-Path: <kasan-dev+bncBDRK7WUAV4ARBFGI2LZQKGQEQP6FHQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf4f.google.com (mail-qv1-xf4f.google.com [IPv6:2607:f8b0:4864:20::f4f])
	by mail.lfdr.de (Postfix) with ESMTPS id E5F6718CC3E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 12:08:05 +0100 (CET)
Received: by mail-qv1-xf4f.google.com with SMTP id ee5sf5356154qvb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 04:08:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584702484; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlmPw2LnoscHyUbKc9bxf1Jo8AM6ABfSEmiDz/bW+aEUS+QqZe7XdyiHYV0DkRwPp/
         cQUgGz5v/fS1TyJ1XAvwUzVtlk3yj1yO3v/+Nk0LryrvGjXfjWz0LNE9fKgpjJhaRT1/
         rbhzPUovZK2NF5wt992FCobdwO4hjZo812HqpniPjWORFHMumRGswXsI0bnb88tg0A4e
         50PkJH7XY6u/FW0jVzrSLvSoHM/vgUtKXmNElb5v2dLYuSvccKpdyLiI3y+/ADhqGBTA
         FFuSBheT4b938HX3NmWVREwXbZpA6lY3GAMM0XMYcXMW9L+QLI0baeIfpIU/6M0O4Rea
         ajGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=NaDcslXgw9TVjUFAvcDNQU6cazokT7VRhbnwwVPNb4Q=;
        b=Rglbep9o3o1tjm5eXvbBOzHRTQ+Lt4yEHVn3PeI8vJo0fNT1DCV3S/IzbQWnWi5h3Z
         QlknUQUU2hJwnkexYufQ6GIdzBfRN1CceXKnxIjpnnZprGiadajWLyO+L18ferEdrHaA
         PujXBt4kL5R4AmGCG2qEkXH9+knqSNgtacnv+hjzq+JzjsJTwj/Ji8lT86AW1EjqNLcG
         uvkj+Zq/v+QrNnBTnSbK9gAYP3glkvBvCP9flEkhN4+k5BWVCgvOgkgD9T+jw1Uxb0NY
         V2z6PWj7wuEpUKN8wkC5P9Uu/GIAuSVxO+XWWzPYfr1rur7MMF9RKenc5UvfqXNSCpeJ
         8YMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Kcjom3Ny;
       spf=pass (google.com: domain of federabureauofinteligence@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=federabureauofinteligence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NaDcslXgw9TVjUFAvcDNQU6cazokT7VRhbnwwVPNb4Q=;
        b=P2Oo6elHfNGIux8PblF/agP3V+xDZkiEPvHjikGwrqlkv9pUhimbqZTjaM37aUEDgi
         mjr1za5h4Tdg+E9G+mV1oKiLqgFoGasry6VSTxZKLQZXKFhadEF5tgSdALTJSezVe8Vv
         XzQc7g2CoP/TB7UIyxk7MW/ljzJwdNo0deLCyBfH79kEw7gFCgejESImFoOCyEPOxhNh
         1SfNwg+vfHHkJlcnQ8/CI1cq4XObi4MgTYwUf/8PsaGHV+H+tfKxjh2T4K/Ems2OC0Qm
         sHd/AtI9b+vEWy8b7+zqKObEk9zcrCLxu1yG7BghRxe9x6YMKlbK+IXzQCV8QsrRjggj
         MvDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NaDcslXgw9TVjUFAvcDNQU6cazokT7VRhbnwwVPNb4Q=;
        b=qKnVZPYnFfnWLcD888F79oTwnb74aKuerBiPYsUICOxAu7lw7fpWdpHP9zr2f4lW0Y
         FVh22Eu2+r7wxxhXkrYVrY8/W3eNTJV4oUMv0z9AgenPT7EvKzZLpPMVyNbWRj/RlEwX
         lfSX7CaCR6Mi0EohbTnvO8tqFp5Rt4utEbwN558nudKXwz8S7lgmNodiunaXFUxXz4zq
         Y07Rxg/9C4dJaPb05jeBV6ZlYbAKpv01B1EEUwG3bEv4fKHp8KqTen1YP7DRjCJsXAOG
         v2zrWeAw7aCFWZAMzlnP11J7VYl4EFZXB4KZBfSyIe5FzZlULTtZnL/LGeaeIceLYho0
         tpWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NaDcslXgw9TVjUFAvcDNQU6cazokT7VRhbnwwVPNb4Q=;
        b=Cfl3KgsrQZCdUqghMylI4KWEESnmzKvzhPuQQ247G3k2l+v8SM+FQLVb7VJDs6Po8V
         eWge5TMTzVxNV/fPKDLVqImlmT5P9ezvxa+ggSJwWlwBIwflcZOYx/sMbCeaM31CUGLA
         F8q3qqTG9R4DNOuDbJ7xFpZjJ+Of7s6ch/DElVXmGwKcwlGSIIB4k55jvALNK1MZu/1+
         wBClHy64xpfqw/7kE5M39R3Ny5yX1qwaHexo+MSzfveaOlfTIia+ruOdmlUC34f88e2/
         w2PEE5paJ6UVKqjbVZU7yhuKj7Z5K97hvkTu3G4inbj9RKN2dH+KHtsb23kddDJ+pfzW
         d5yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ26MUp+zP50HLmlhllIn6RUpxCkwQdYhdAvF8VG1YajnEGk3DY4
	c23ObKnDKB4eCOT9uN9zHJc=
X-Google-Smtp-Source: ADFU+vszPZ9AOORZ/br00tKq2EdtIG9IVLyC4L4rgi4+/aguCzELCuuc6n0NZTiEn1rMn0SD3wMbJg==
X-Received: by 2002:ac8:7b24:: with SMTP id l4mr7556397qtu.17.1584702484698;
        Fri, 20 Mar 2020 04:08:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:efc2:: with SMTP id a2ls1296398qvt.5.gmail; Fri, 20 Mar
 2020 04:08:04 -0700 (PDT)
X-Received: by 2002:a0c:fdc5:: with SMTP id g5mr7710501qvs.194.1584702484291;
        Fri, 20 Mar 2020 04:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584702484; cv=none;
        d=google.com; s=arc-20160816;
        b=MCUjCqjEDOkIyMjMUGnhSzff6Ch868io/VZvc87l0ufAHWzrpN0p14XUfbJuk5p1yT
         fGkh782aUt1DqDS7uhQdXrc4pTVKXHdmhIU9dx4GpQ9k9mLKnrFFrFsbUVM4GzTnbYiF
         JA4ZRAeUmP5DwJeAnpLmM/lQTti7+B7kNtTog7/tlY0ZdgQQYcZaLNJaAc/BhWyn1INW
         9Sv09WONyh/ZmpYS8/v4GeLp2LuiJqkMPzofxn18L7oiVx7I6ixbfJzEDDq7rRHsjScP
         LYuJSd3pohGOnMs26swY1QNys7+7bklrjUW17AvW2x7xBmMHvJsIljAJfEK4Zc58RjSc
         PbpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=kuhba0bbR9oJup1oQ7P5tNPZ9FqBHXE57QqcfHgaIHo=;
        b=H1XEJA4o9EpiAerN1bjbsI6Wj3Cb8zGsqQR+KVj+3qmsfcBfh0iP98OrFSP4MmINgS
         am+RWknVTNQH/N5jDZ+fAz/clNGLnrC1SIcrjG07ArY1pZRbQ4NhJLgzp8aDQYKS6eHB
         Vi4Git2asbxWJIMA1s4Vu+PvuP5fBVaUuayTDwslO0MFconi5zCtxa86uokiyX13cbuk
         bnWw5LFc/Qg4JRMw4uwgEq1+xDWlqckqMGAyZLgLBgVfksz172q6AHsMFNnsLHIzcbkT
         z7IyRdp+R1uFcgXxHu9Ew3ieQz7ZJHkOgSLMiF6yu6loFpHRFo9tEf9bsQUUywS4bvVQ
         XuRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Kcjom3Ny;
       spf=pass (google.com: domain of federabureauofinteligence@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=federabureauofinteligence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id n138si277575qkn.5.2020.03.20.04.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Mar 2020 04:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of federabureauofinteligence@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id p125so6018195oif.10
        for <kasan-dev@googlegroups.com>; Fri, 20 Mar 2020 04:08:04 -0700 (PDT)
X-Received: by 2002:aca:3255:: with SMTP id y82mr6102866oiy.44.1584702483981;
 Fri, 20 Mar 2020 04:08:03 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a4a:c897:0:0:0:0:0 with HTTP; Fri, 20 Mar 2020 04:08:03
 -0700 (PDT)
From: federa bureau of inteligence <federabureauofinteligence@gmail.com>
Date: Fri, 20 Mar 2020 11:08:03 +0000
Message-ID: <CAE9o6LB50YPWezLwrs9uSwCgfuFuUSrTfGz=QiaO9Pj23qjovw@mail.gmail.com>
Subject: HAPPY SURVIVAL OF CORONAVIRUS
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: federabureauofinteligence@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Kcjom3Ny;       spf=pass
 (google.com: domain of federabureauofinteligence@gmail.com designates
 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=federabureauofinteligence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Dear Sir,

HAPPY SURVIVAL OF CORONAVIRUS

We are reaching for a very interesting business transaction which we
feel will of great benefit.We the FBI unit in the western subregion of
Africa have a fund which we confiscated and lodge it in a bank

This fund is worth of $12.5 million dollars.We will need your
assistance to recieve this fund into your account for investment in
your country.

We will need your urgent response for details

Inspector Greg Adams,
For and on behalf of Cote D'Ivoire FBI
Tel 00225 6716 6756

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAE9o6LB50YPWezLwrs9uSwCgfuFuUSrTfGz%3DQiaO9Pj23qjovw%40mail.gmail.com.
