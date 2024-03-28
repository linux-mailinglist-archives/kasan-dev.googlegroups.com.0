Return-Path: <kasan-dev+bncBD2OL34CV4HBBR4SSSYAMGQES5XA5TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id B76E088F7AA
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 07:08:08 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-56bf2d59fcesf459998a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 23:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711606088; cv=pass;
        d=google.com; s=arc-20160816;
        b=xnCzlno6gmysD2hPIKA2DCLk6jjE0Bbx+KN5PQ9BPl9dlndYQROKCti9QSdqI+mGMz
         20hU5Ujyj2adOOaRORGY8fKI3/nYCC+jQveWOAhEUAWJ6pMyxO4gQ6rQ/U2mWuUW7kTP
         ouBtCdMHXz49VhGcivhJZ7RT7FEZ+lUNBVg9k5hdIvaW8nHCEF7fBaoryLES3VxzoPYY
         OUskpWcRzxE2gefdM+5pxO0tBj5ZRK/eNTYAf4r1wsTKHB52YMsDBZL73GGAwZ0UI6ly
         XX92EsW28chkWBgUEKoPTobS8jIF3mr3ZXON4E9EL9jzo8uEhWwyMs93fQ/7JN4Yc7Ze
         jckA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2UdYW8ryCFxfelUzfGFcplPKX3vQOo9s4nsoxVkvsiI=;
        fh=lwxdzEs9GMqpfalKct2rGbWizCXvNtF6qrqXe5Bth3k=;
        b=Yo5ijuc2wzTsdHOi9P9PzrhTMTSK5cpThVY6NyclnmZD9kOF02jQGm3ReeM3mCkDTv
         /yVFLaVcih7TV+5xJPVfYzTEYNeLkskVghh8+5oMsC74LdTnI5YjeyQmAfqb9yC66kIU
         H6MPrfYRh9aVp5Ww9+xgpP8PvDccRxd2BW7C0HKABB8bYqcXxB/dtkNNXY1w2KEI3q7J
         9TKNZOAmbsRP0K/sZqg5RekLTmdDIdxpmA+aHCJMXPVsTDeDEc3Du7ryYjpsJSIDAAOX
         1Ca5boIvt31s5IicqAmFyJKXAqlzYM6vs91viBgR54J/D0G7kdBS4Hd3aqiuhVa5s4Eu
         ksFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711606088; x=1712210888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2UdYW8ryCFxfelUzfGFcplPKX3vQOo9s4nsoxVkvsiI=;
        b=AsO8fBV45cSmpIDvFpexH5gaTOKYqrsK0u/Mk6uocXB1EF0OoAe9LNotxE6F8hSESF
         rH9VAkHw0W2lljBgsS2dZqtXa32PtmlEljaTdfQGR/FCL+uzRUhZdef8vI7853xAfczB
         xQaaUNicP56OU/QzeVwzLbvsjQe7lTEtJPElJtUeD2ixkrFoWCgyLNicRZBLHcLKVerJ
         Sf33a2G8/vT+xEKtRJfZH+3pOMM7EY3rIghvMRs9hKMfiSJhzbmmAAoBieEha5xPgB+7
         K4gSHVSh7r6FDUnP4QBTPWZEHc/yp5L6tgmfbuR62LHrBpjk/p4KpbDkzHvvYm0fbF8I
         Ginw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711606088; x=1712210888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2UdYW8ryCFxfelUzfGFcplPKX3vQOo9s4nsoxVkvsiI=;
        b=elGxnDaZgnTTe23xDInALBnGs0dQsTEv11ZTqX4+GRpPbMV8TWPQOE6+rIv+3XwhwL
         TA0M/ODL+DEM+tnnGx2rRF7MFiXBzCdvtiRZDwt2Ox9tfhL88oZ9mmh9eLnp9CEyLjx7
         4yFlxD6I9r6VBVbQD1n1xD/YVdUjt9TXqAVT9cVBIUCkKsrZBJhirTb5YZnu1/T3esHo
         mPjqH1TfkGXMGVNBaYJonl75e1dlVlCZ22POMZy4xzhzX4D6jG2QJTnRdCKjmKHFGNlT
         azfbY8EulfWwzPQseAJitc+R7fcfLx4BdGIf5HKCMiv8ItWVZrSH1XC0lbBxzD2R8A81
         SA3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN1AdH4FKT/HYBM9eUlmtKqvqBXWto4RAAGL29AFu8e4i6835rXrPZ4qpPjuHBxWSBTBLFpY+3ldockeJ/KObww+DGrSZjCg==
X-Gm-Message-State: AOJu0Yz+O4+NrD0z2G1qRApZXdM68y6XDLEsaroKOK4tQyXRepj3UgRE
	m+ZlJ7AFYneXj7U5XM/SU2AC3j/DnLvTLomPBhWgiVuHHJd4+HLh
X-Google-Smtp-Source: AGHT+IFpLSXqQzNzfj8AGb9zlgReiwFnRoKK2avh5ATcpBtYq5suwD2xujTD8rXBavIIVyv2Z1zVrg==
X-Received: by 2002:a50:ab09:0:b0:56b:d139:490 with SMTP id s9-20020a50ab09000000b0056bd1390490mr1235483edc.6.1711606087292;
        Wed, 27 Mar 2024 23:08:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:268a:b0:56c:4cac:5ddf with SMTP id
 w10-20020a056402268a00b0056c4cac5ddfls192278edd.1.-pod-prod-01-eu; Wed, 27
 Mar 2024 23:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVOOH+7ishMd5o7O0PPAEqpGBUZTAPOsXwQBVpkf1TIvYxGKbtGr5NU+zEzsiDJvSYlJvw1v18F6QcFxovsqRXRb163KIHG3u1eA==
X-Received: by 2002:a17:907:9488:b0:a4e:14a1:fa81 with SMTP id dm8-20020a170907948800b00a4e14a1fa81mr1083039ejc.46.1711606085111;
        Wed, 27 Mar 2024 23:08:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711606085; cv=none;
        d=google.com; s=arc-20160816;
        b=CYv/UYegIWPDFDFegnKMkod/KJF2sMdxjVOJhZ0XCSh2H/AmfhC7honvxsLxiY+Npq
         I1TcKz8UyCRQMguXiJBccutkC8hruA2Bhmxrwv0VRN5W0WqnhDZn9e4D0P/q2mq4CLng
         Oo2fwUcqgOp4PtGzOLFkMsMHjKudWx23yuXadRbkzIxXb+gvbF4R7agdh+JO/CNQGod+
         Vr6uQfyJZX8hknGeUzeWIKnkUrvtHVwTpjIN6uKz4GMOSTKXPZEJKm+0bYHp9N+9tfv0
         kcoeLCryaTRCmx3Wouw+4+Kx+99bxbdShS7Y/YMlD4y2VPrTvc3kigMW065guy9uEfZp
         ma1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=TKG1OtVr7vmxpuT8g8J3sW1oLFa4deg8SQ01vdYF9uE=;
        fh=V58IpNzeQsyNwNa5VLhLRSAaCQQE9YtgETGfhvkHe8s=;
        b=FGKhbZ0L/DXXXhEc0RdBtTrWW/9sXprNJt87r1ezxIRqy+tV5uphQyMZgM8R7/jYHv
         0JQY5Y2hMs2E5y6m72g9VRsrJ2xllCmKHz9GGrOb2sf69Ea1nSbIV77+q4uc9hsn2jiU
         o051zfk6fUzFmAoorpk4zqWjKb1Ep7mVQvn3U/eA967urz8O3k+2BCa6ToDiw14F+8+k
         Z7NOqFQoBaVk8l2y0RLqVmpkABaaiCpNj3hFk1QI2HhN7CtYKJ0BU5E4kfb+QFaGMOR6
         fbkazRXTXiiY5bVK52Ne8eqZLH3ytJ2rpYd+IyLv5JL17B1q8r8stR7CeGTH06Ayu+Tp
         RQYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
Received: from mx3.molgen.mpg.de (mx3.molgen.mpg.de. [141.14.17.11])
        by gmr-mx.google.com with ESMTPS id qk13-20020a1709077f8d00b00a46acd22106si23345ejc.0.2024.03.27.23.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 23:08:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) client-ip=141.14.17.11;
Received: from [192.168.0.2] (ip5f5af3ec.dynamic.kabel-deutschland.de [95.90.243.236])
	(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 (128/128 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: pmenzel)
	by mx.molgen.mpg.de (Postfix) with ESMTPSA id 39D4961E5FE3D;
	Thu, 28 Mar 2024 07:07:37 +0100 (CET)
Message-ID: <a3dc1d15-a606-442c-a530-4da0abf1662d@molgen.mpg.de>
Date: Thu, 28 Mar 2024 07:07:34 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c
 intermediaries
To: Borislav Petkov <bp@alien8.de>, Masahiro Yamada <masahiroy@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>,
 linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Nikolay Borisov <nik.borisov@suse.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
 Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
 David Kaplan <David.Kaplan@amd.com>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
 <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
 <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
Content-Language: en-US
From: Paul Menzel <pmenzel@molgen.mpg.de>
In-Reply-To: <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: pmenzel@molgen.mpg.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as
 permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
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

Dear Borislav,


Thank you and the others very much for coming up with a patch so quickly.

Tested-by: Paul Menzel <pmenzel@molgen.mpg.de> # Dell XPS 13 
9360/0596KF, BIOS 2.21.0 06/02/2022


Kind regards,

Paul


PS: Without your patch, I also so it one in QEMU q35, but not consistently.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3dc1d15-a606-442c-a530-4da0abf1662d%40molgen.mpg.de.
