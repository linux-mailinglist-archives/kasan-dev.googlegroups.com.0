Return-Path: <kasan-dev+bncBC6L3EFVX4NRBZFNROYAMGQEU5MFJJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 36F6C88C493
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 15:08:39 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2d478badf3csf48332561fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 07:08:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711462118; cv=pass;
        d=google.com; s=arc-20160816;
        b=kFeJUvgecORkj5MtMSFXRyJfkwyEmb6GJ/gMrn4L4gh6H2c33B6hemVhUlHkalB6W9
         ZJ8UT1lsiiS7hnTsmW0PBX9G7bb1UvDFsTnsuwhjc/BhH9n3Jjxd0tkGqjcQ42kfs5Wb
         bpSBKFcHKwYj5ErEjA6G9atTaGcn0BqQ3TMyiIvc80sf1s5k3gMF4YPAMj6pu3LmbA3g
         3DnX3Q3ePuXpfhjqSmyviVe76kI8PSKz8E1HRFDlJfr9IhtcrcaQnpRBnWbMFb5pE1q2
         ghPdO82IR2wvT52r3uGdsNNqjypiVHMoKDLXQx3mgEJcpgyQ1bamw0wKVqj7g80v0diH
         ElvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=QTEfjXySX78H2UWT8QevD7UZO1LGd5vY3HUcocA/RCo=;
        fh=D6yK4VAKfg0m9+34MGGVzOys978RKd7CaUOqBdmd5io=;
        b=ntv2yyGwPc6byLui0YL4Ip5yM7UHkiq51LAy9l5+SDX3nPF/iXW4Z/HyQQNgreJEQy
         hP0Hs2X5QHy3VyyhPZ3Ni3v/1u4iWQhMS2tjSPi6WKansDIh0qyly4csKfq82oYs8/8O
         LmdQKgx+4fn2/ly9UpkT7wLjbm7SwTuJbRaIWLl3asokau/ydKcuYmqeoJJtv6Pzpjun
         8ngeAsu93GVNDSqCExbw8si+qiT/UT+BUT9Yss/EDzO8v63QHrBpDcyRr6YoiIGCdiRb
         55tc1j/YAB3YfzrAFcIBKqkwFNR4NWfn2X6lv8GBVaGbu3riBwCIM/50QYBXToSsYZR6
         tE+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=K5zNokPa;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711462118; x=1712066918; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QTEfjXySX78H2UWT8QevD7UZO1LGd5vY3HUcocA/RCo=;
        b=NMc9kFOXuxzQYpVzuQITXBYAv3b0aT6QGxNTUNswP01sbjZi7t4k8a6UzWJ9zRWxCZ
         xjzDs5bSslUpriBi9UK9joK0EyB3fm4iFnAPaWOt69mmaYjj0MqpESqpaWtPQMYk9BUS
         UfvpHn6nT5/cVUR6iyd2JdKNTl3nKu4ZVvqo/rfQj6udvlx+WkwnrVsBFy8ja4kqoXzy
         nHGOql95keVuILdTcsefj5Xjq7UZDiSOnLdpJDepgF/6rVRndYkcNOy81pFNNCAdhnXe
         7E/cyTYNAUkcbmns63GWijkwPOqdhCRwQZO28QKPCdIz89IQIHJPRm5w4IXbwyxbh+dO
         iqMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711462118; x=1712066918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QTEfjXySX78H2UWT8QevD7UZO1LGd5vY3HUcocA/RCo=;
        b=XtGpOD2aEAvxYhQ/FJ1AX4jgcac+Z520sWXtSamUunT0IT7e/nw7EI2Ghv0GvKtx0F
         4ToO/tGValtxK9fEk3WccSG840Yx1OiHlE3QZQyXNn3xtC9GBgry3+Mvre2p1u+mWMGY
         1I3jyHoeS/o7sDydf4Q1Fs4XQreGqsCn/CrLW4Pn6yOhBkXRw/soFKsjJxM/IScNuyhV
         zdFimyIyYKXvAZLIW0HfPdpfg90ngwBpoaRs0A6OQVXiyV241GW0Q7kfFUkq2E0+0k+0
         h+rNQt0OsXqtmVz6ZtyuX0xd2wtKeJm6/JnrJrfapAxWDMbPy4fKR0Qq2G+f2x9g+B1g
         kyWA==
X-Forwarded-Encrypted: i=2; AJvYcCU3a4xuIt/0etgHglH1qXUXl3d0ckujIfCqZwgoRccKsXa/4vzsvz4TrMDIAQeT2IbluhTBTKlDZ+7LqnpCjYhBqBkzQFbwew==
X-Gm-Message-State: AOJu0YzRU7cgMx5laoTvbWiY5VMrc3Cl0+8+y8aZ76mN3ClDBlT0dFw0
	mRRb5OCggb4LXqLp34YEavfdNLyTlqf66zxC5jDdv8/cyOZCkq1i
X-Google-Smtp-Source: AGHT+IGsHWz2Lo8/NUC631npIISsJqmhB90j3B2Y02c30glww8fjCXX8ORNJaaWUc8dM3u3o74z1Yw==
X-Received: by 2002:a2e:2c16:0:b0:2d4:37eb:21ad with SMTP id s22-20020a2e2c16000000b002d437eb21admr6602688ljs.40.1711462117105;
        Tue, 26 Mar 2024 07:08:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9009:0:b0:2d4:4b34:fce with SMTP id h9-20020a2e9009000000b002d44b340fcels254490ljg.2.-pod-prod-04-eu;
 Tue, 26 Mar 2024 07:08:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh+2a9gzBujs3r1/2GeyObgQMgBjyVUgfb6IktkngU5PICP6DPBLTzydzNlXHPZP2PDbxYZvuFeBaWZIs6/8rSHwZhoOxJ2LDwmA==
X-Received: by 2002:a2e:2e04:0:b0:2d4:6c52:23d5 with SMTP id u4-20020a2e2e04000000b002d46c5223d5mr6199343lju.50.1711462114826;
        Tue, 26 Mar 2024 07:08:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711462114; cv=none;
        d=google.com; s=arc-20160816;
        b=lV0I13ICZuTd5qJVa07eYg2jNFk21z9cTC7t+zMP/4xzpuH+p5MR0+lAm1AfF7l3+4
         98LUZj4A8puoL+l5pytU1yMnqlr5ZD32bikfyMQx9sDdTH39C2t923uP8y8wYdieXhle
         jBqmSCo3zZFN/bS0IaTvVyVZlmEhR7N42QPO1N75onBHzl5U1aknqmt1UoupWCtLQ0Nh
         ZMPAtlIbRB5G2OhOsVTVHKD7E7NPPYFCGG9fCzlHHPJ9NGjoMO311YrijGiP2opEMfce
         DwMgHdcFSPqhIBRuUIL10jse+n4XTkv7e9+teiZZbgzXtdOxODCf5DDcjHATASr+6k5O
         cjbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IFJbNRl2jhD1FZpGYS71X7jv5bIbfTuIVkI+Wa5VuaI=;
        fh=1QB9lX2hS2mfPHKTGKTieRQC2Tf3HInwwVoRV6IjbBs=;
        b=0RssuWy6KJEFPJfXBH+d7nYfEQWYR9lS3Uy1tkIrR8+tBk9ERggwpRLdtFbsMdarOg
         LR1DksHfX+XWjKfMIY47jbaMkSXeyqHGSapSyzUy00peB8dcZbHB74VyHAvRUlwjxPDj
         wd67ZotEdg8po7YnxqBeM/zuIqO+Ol/vv8Jk80mwGlhSksmieK8UL3B51II1Xwxk4z98
         r1ikfRsxgCH5wXwJxYuXwyRqMrWmNisEozZVBjO2DDWvDYkhuCpIPmExzhR6W0j/ZmC3
         QBv9ZIghZ14ADWNaLPesBMIUMeuUkCHGysvB42nhTTP8Ee7MnKyHdc/Dn7uM1PxO6QWK
         Q2gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=K5zNokPa;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id x9-20020a2e9dc9000000b002d22c31334fsi328492ljj.4.2024.03.26.07.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 07:08:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-33ececeb19eso3668918f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 07:08:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3jmoK/8xw4Ve3yC5ejz2AxVhxmSXaTzQaEs12hISJ4/P9295BdeZSKVZP6H/VEwKri2SIgqQTpheO/Y///XBPJJ+P4RKG15laxw==
X-Received: by 2002:adf:fd07:0:b0:33e:7c3f:ee0f with SMTP id e7-20020adffd07000000b0033e7c3fee0fmr6663741wrr.28.1711462114116;
        Tue, 26 Mar 2024 07:08:34 -0700 (PDT)
Received: from ?IPV6:2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a? ([2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a])
        by smtp.gmail.com with ESMTPSA id by19-20020a056000099300b0033e7eba040dsm12362850wrb.97.2024.03.26.07.08.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 07:08:33 -0700 (PDT)
Message-ID: <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
Date: Tue, 26 Mar 2024 16:08:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Unpatched return thunk in use. This should not happen!
Content-Language: en-US
To: Paul Menzel <pmenzel@molgen.mpg.de>, Thomas Gleixner
 <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
 Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>,
 Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
 kasan-dev@googlegroups.com
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
From: "'Nikolay Borisov' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nik.borisov@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=K5zNokPa;       spf=pass
 (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=nik.borisov@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Nikolay Borisov <nik.borisov@suse.com>
Reply-To: Nikolay Borisov <nik.borisov@suse.com>
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



On 26.03.24 =D0=B3. 14:40 =D1=87., Paul Menzel wrote:
> Dear Linux folks,
>=20
>=20
> On a Dell XPS 13 9360/0596KF, BIOS 2.21.0 06/02/2022, Linux 6.9-rc1+=20
> built with
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 CONFIG_KCSAN=3Dy
>=20

So the problem happens when KCSAN=3Dy CONFIG_CONSTRUCTORS is also enabled=
=20
and this results in an indirect call in do_mod_ctors():

    mod->ctors[i]();


When KCSAN is disabled, do_mod_ctors is empty, hence the warning is not=20
printed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/47e032a0-c9a0-4639-867b-cb3d67076eaf%40suse.com.
