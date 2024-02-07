Return-Path: <kasan-dev+bncBDL5ZOFA3MARBZOZR2XAMGQEJZJPRQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id C4C2084CEBA
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 17:16:38 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-783f387ed7esf99956785a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 08:16:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707322597; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZqxyVpdtAhbONRH8fCdMCdi+xcN+41NqNYKPeG7whzFe6O3BmRoBC+sJBlecPKk0j6
         G68eMHc5vyScjO6kyWIeV1hShWY4buySicIYH05Xm4REbWGWdO7EcB7zKzkH4ok08vjj
         YdgTfNoW97lgYsKVwET/9zmuykJ1Ca4E+jyEkBsRjKKZJq6epnO1xQX0GjUDTI/p3x1t
         LtqDAc1YPb0XQbbFnL3ZryRefihlQFuLXqzWmvzfjz68OyOqujFUfoJIxbLO57QPp7D3
         pBkOtsqfFOHOyhJ1LUWCP4/9sFowGN+FEk3GOC4gLr8/O+CjUxr6Oy2GK/gSr7wsCPb3
         B38Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:autocrypt:subject:from
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1JXIy39rPJGjmYFt2xB8L2W0XUCVh6xeRLZhHIKngJg=;
        fh=L3WwaI+5gC/tJgsgIG3uZqankq3FN4iGNcLpugzpF50=;
        b=w9Doim2+MBq2tr4ovSMHof1laIO2TVrqe4rJJRGsOgZOghdPAJ5CP+Sp9D/pA0hNYy
         Z/DxCGW8OHtCQDqhKrq/UkoFMlUR4fQVwKGRYvmezxPGfPUqk8YW1gHGinM3EI80Gz80
         8wN78O6jz5Y87sIHTK/+pjp6n3YlAZRvrU+S2LL/LdRBbUX9HcnZTQPDjTkRJGq06VhJ
         CNLeg2iiH5xEPd4MKt6mv6gIVC6uUWvstT5ek2pVrg/97byQSROZrPvFEcRMFyBJpSp4
         4YlscxB73rgo5+Ec17x2zuyBY6AFbcFGbCxNk/XY2HYS0kvT1T0/FLbsQE8v4VnI3CNa
         m6AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EpI6HsMc;
       spf=pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707322597; x=1707927397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:autocrypt:subject:from:cc:to
         :content-language:user-agent:mime-version:date:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1JXIy39rPJGjmYFt2xB8L2W0XUCVh6xeRLZhHIKngJg=;
        b=oh9qnCohRqbHwoNQhajHYhFgrfZ2HWhMIHJZAqVz+Eyt86MPCaiaWVrnbEEkNa8P+p
         PfzuRhYumzm/OLX8GaWPuTW//tbRGbTIgg6tM3i78U9/j+g5RFHLvTkaO6qZdsHPXLD5
         7ilPbrtnpyTsdHqjT7A87DSxRYhkM8DfNAktL/SXXNx7NRrSOnPzttZ29I506xjN2V+i
         P28EaYwNcCfiRifDvI0nUJDq3poOtP711n9j2BnH+NNuc6I9q3z0OVekn52oWy7q0Xf4
         zFF8eUeW+br/4kFtcyj8F9LNYo5AXjd+kkPpXETLmVuhH9UVWK6oTP6RQJ2h/l8Qr+Wp
         XY9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707322597; x=1707927397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :autocrypt:subject:from:cc:to:content-language:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1JXIy39rPJGjmYFt2xB8L2W0XUCVh6xeRLZhHIKngJg=;
        b=UAZD1JYoRNWdOune5yDhW/WnG9FtIYcw+eSyykTKTg15ksyUw3oMhAAH4QL4gQSOpC
         fxxAHegaKNKNEgG+BHZ37oN2lf+TroatXoG2mn0pkEC7PaIzUDHzkTcCns2EMAWtMolS
         m3Te0epgfFk183bWrMg+0EIWL6ZuAxenofjolzI7iR/EeUl4hhjpnyZFTGvwkybotrjS
         E3ZF4InHdJZ1YYSM3u52Az3veNPihxl0WJTPGWWIYFvs32OJ/PvtANm7ilFIwr4Duast
         0KOR9z5gUhQ/BTU4F7wZPF9IU99nxPWhi2s6spNrTANb3UTiDJWmHmdcifKKiAil6+Ep
         oJFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyz+1C2B4Eqs9dIgahLKXW4XhFE6wu+zr/LL+iG5rQMoNlQimf2U/mHQ4eSeNaxnYg43m6IRVKYSoQAY8IeV8ZggG6HBM4pw==
X-Gm-Message-State: AOJu0YxVUM0NWMPiF9kmfC+/dchpAPB2PQaJxNKGhyP+I9f4GhRzss//
	d6qAglZTdAQA0kwA80KEAvfBRAN3ejI+Q8o4s9yCKlI7jCF+EnNZ
X-Google-Smtp-Source: AGHT+IHjYNVFjfmaE33YGdl9pYxW5VKuAetWlS2Y8HXQ3cedt844HLx2hnGlYE6pwmeHH8WuC9bVrw==
X-Received: by 2002:ac8:1d02:0:b0:42c:2998:dbdb with SMTP id d2-20020ac81d02000000b0042c2998dbdbmr5722160qtl.11.1707322597408;
        Wed, 07 Feb 2024 08:16:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1b8d:b0:42c:134e:463a with SMTP id
 bp13-20020a05622a1b8d00b0042c134e463als1622897qtb.2.-pod-prod-08-us; Wed, 07
 Feb 2024 08:16:36 -0800 (PST)
X-Received: by 2002:ae9:c10b:0:b0:784:ba4:7042 with SMTP id z11-20020ae9c10b000000b007840ba47042mr6122511qki.69.1707322596467;
        Wed, 07 Feb 2024 08:16:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707322596; cv=none;
        d=google.com; s=arc-20160816;
        b=QPSdYzq153y4KfBvX10bDxMFI8eSjecr+apautGMKujZEo7+Q8d4Hp3OWIwnO+B//x
         GEz5bw5YNF7L0ihGqLdohlpw/kN+VMttPjsUT8S32JHnNQOZ2ff6DBV/zeWCtR1PAZg3
         45dLTb663UKV7p/+F+OlhWixuE5LRC2NcDqcJ6WFxcg+fhRUjIglLh9DLRlqut3Pb7OV
         IM3OTmZWF1QwJjX/brymetZKefrixIy9Iw6uH27D6uUS4KpL9aWrWLrsAbV+o8K0hesb
         R3Eyj/YWR4EDhI8PB2iuVkNl+5zJvm6GXBWj7wb5n45gfz6y180fvAJrpGMKLcwEDjIX
         TN8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:organization:autocrypt:subject:from:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=g1zFdnNUZs178HJ6+K5cRwaz3nAjNkSbf0YgiZd+tps=;
        fh=IAG57g0nxqaFU1eYpVDRlhYSGh0Tl6NxeC14unsBROc=;
        b=PkHFCAqvMrcpBYBHlY7cTr1WaweGGBc/Zs/PfBtwBz7eHo/4A0VD9/3OhmomA2NOhA
         mUXmWS7oNtWrDp+UgkA1UB1bepIs8b5V90vtAzA6xbIWSh0yt0rXZaSMdUgbkWwC10ca
         4BwfeeCmOBKQeUQeaszEH/KJN+2O9o3uRQCHG5cIXJNqp3u8fLA3P242McItdR+aLHsA
         oiWG2SMszIr75DYAvN4z97c5i0M2i59OQTS/oxHAjVbmX7AImfWYhcgSujYaeFruvLTG
         3HftYO16oi/g+yMgCbO3mx/aIyd/gBj3mzrW4nOVUz/4a1oMjkp2P7Zo5LP1gchvlfdW
         g9HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EpI6HsMc;
       spf=pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id tn10-20020a05620a3c0a00b007859f6d3be2si109864qkn.2.2024.02.07.08.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 08:16:36 -0800 (PST)
Received-SPF: pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EEDCA6181A;
	Wed,  7 Feb 2024 16:16:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 50BE1C433F1;
	Wed,  7 Feb 2024 16:16:34 +0000 (UTC)
Message-ID: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
Date: Wed, 7 Feb 2024 17:16:16 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-GB, fr-BE
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, Netdev <netdev@vger.kernel.org>,
 Jakub Kicinski <kuba@kernel.org>
From: Matthieu Baerts <matttbe@kernel.org>
Subject: KFENCE: included in x86 defconfig?
Autocrypt: addr=matttbe@kernel.org; keydata=
 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
 lzVbFe7fduHbABmYz9cefQpO7wDE/Q==
Organization: NGI0 Core
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matttbe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EpI6HsMc;       spf=pass
 (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=matttbe@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi Alexander, Marco, Dmitry,

I hope you are well!

First, thank you for your nice work with KFENCE!

When talking to Jakub about the kernel config used by the new CI for the
net tree [1], Jakub suggested [2] to check if KFENCE could not be
enabled by default for x86 architecture.

As KFENCE maintainers, what do you think about that? Do you see some
blocking points? Do you plan to add it in x86_64_defconfig?

[1] https://netdev.bots.linux.dev/status.html
[2] https://lore.kernel.org/netdev/20240207072159.33198b36@kernel.org/

Cheers,
Matt
-- 
Sponsored by the NGI0 Core fund.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e2871686-ea25-4cdb-b29d-ddeb33338a21%40kernel.org.
