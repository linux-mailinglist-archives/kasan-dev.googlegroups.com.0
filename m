Return-Path: <kasan-dev+bncBDW2JDUY5AORBAUPVG7AMGQETHPGS4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B350CA55CB6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 02:10:28 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4394c0a58e7sf7905615e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 17:10:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741309828; cv=pass;
        d=google.com; s=arc-20240605;
        b=NWYRnJnA/hlzRA9CJKWHlP4YYohj0t0fbyFcvFx51Jnjd3EJ/+ZHoCQ0pavAWxDm2E
         rnwly4LKw7u6yWdU32z0RqARapC+478/MJWBk/neGg+ntppOKNAMfF5Jd62eTRwgZcHK
         3JVsXVe1J34Q0MU3hULNNt/BSdrJ9fHg8t8T2QDIrnnoEZ5fg/J+dqTibbCT/QPavimk
         uFLwH6h5ET5NJcHvbvSKQf2/6GsEipKZhqGWJx+/LzWFfGfasxJbJIA7di5db00w9amO
         1VybbHZzd2nX0pTLM9EYvCwxlLr+gX42vq+J9xdxuj5WLr0RGP8ZCm/RAmeBkLJGFJ/T
         szAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xyZd30o/Oim2ZvvBr8LjnYM9R4UXEtV7+Al+Iu0lX28=;
        fh=t/99MxjuQ2wh64q0rwWS0tunz8DNAmSKbIeTl20A5m4=;
        b=Jm/vX5tNEAwLOckT63TXaEsxoCNfuibZFPQxzP3qtCSIGoX0boezXDgs97mMUfVBHR
         XkihMTrEaGLJi//aCkawb3sOPX+kaVFHuFJkhVQdYvkstrdTM8tLQDPwr2gnQutKhIOG
         hGeJuCvDgb/JJW03m79uCc+wblRyzUqsLMVsWx9uCxq6Wwd7CstPtZKEzkWO2REeAy8+
         3MCP2lNwMC25z9vKB0aBkpPYdjR6TWiXfgVL4bRPjycAm0UaDODQ0R3cdvhMIVTD4HoK
         Ee0+KEsG7791/u4GI7UhknO30onyw1c4mZi0I5JrfIq6Nx7xf0Hdo8p1br4t8sY09MTE
         jCjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WXV3Tn/Q";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741309828; x=1741914628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xyZd30o/Oim2ZvvBr8LjnYM9R4UXEtV7+Al+Iu0lX28=;
        b=du6WRUwXdAhicLddNh0acCQanFimszEJkSKXN/o+k5LnRztBBCtd61RD0bHDAVHcYI
         cAB473O+FBvPySm5wyk4FkedWW3kBxlsstZVBudfNf2MfcIAifBpOk7xyXPIcKaiCeHC
         INCwH1zrwusZsSBAzqn5MbPb/SbuoTgvPfWVWET1klGBUhEjA76aRYqtI/DhRyC1hfKi
         kfrKvxLwDsMbvc2BcRmLK1vh5QDxCVWLn0nX71ubSjYI74mSA6xYdc6ap+vDGmbCCCnj
         7zEYuwayg4m/I7pYDL7oNYnV5Vx3E8N5KyI2cQ7lXhKYIzb1AL6raJQaARxx/9VX2gCv
         OoXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1741309828; x=1741914628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xyZd30o/Oim2ZvvBr8LjnYM9R4UXEtV7+Al+Iu0lX28=;
        b=dFeX9G+om8JYrd3tiZdoodZa0/7TzLI93YhLWtUYE2RsYQI78eiuV8S6xOv4L9x2bM
         VBoqID4M/diS23EgDsxXgyw35PYuXkvh80YIixbuls57xuImsoErP80tEOR79v5AYJNP
         ktyc3NjWo4FyQFMrzH0SU6NtsIPhr5Vx/zOfwvvM4SFbh4O2wGB2tCrQzSyIdDHLJeQd
         vuhl2bSLKxIDbo9vTuyoZGfYhhhj9WDN5lKwW1ZMcLWx2SHlgqvyKUiphonLbG0ZbTLc
         qvnRGbEPZln0F1ikphhvc1I39sqMAaE8GYw6EC9lO2G72pbZkzPUFGM600I7bKS2RZS/
         G1Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741309828; x=1741914628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xyZd30o/Oim2ZvvBr8LjnYM9R4UXEtV7+Al+Iu0lX28=;
        b=eiJR4sniPPDuj66/xx7gPQoQz6sbznE6UtD3YJq7v33yeAJeLW3fFbieAzj9HZIWuF
         nP1t2epPBXrCLlnO2Bf4ebcB/7xxhzAkks14ZNvxDvmWz0y1IwqJBqVSN43pOjRS3WLY
         C3fFpmf4jcldD9ll/JtZKzwiwD2vyH3nxGfQt+RalH13vQU3e6vbcj2OIuUyrsDBSwdP
         c7bQ2IHZAZfL5pNce1hS5QQ+glX/48hiFcG8ajznsn+prbNf7IUxZ5Br12u/3LKd99k6
         x5BbTya3O/Q+hUankKmu+F+bKIcnn5cLh0pI1LC1u2Qxcj33YuOMjqcr4ceX1Sva8v5L
         e0DQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFj6wFH1XHKbWnNClvc9DmFbnVHXyygOj7ZDhYSZ7HR4YhzVGTGy1CaOKJYQmzybx0MVB3ew==@lfdr.de
X-Gm-Message-State: AOJu0Yw5+zZ9EMJQ9Jbfm8e8au6QwksHybDXIXM1KTv64DtO28TNGGwZ
	SbhJs5rS0lEbioLeKxi1gUaxKvLhA0aQ/IE+X5m2OywPsOwEtiWG
X-Google-Smtp-Source: AGHT+IGOrm/DEDfqj2COb+gmEgInfSP2q2KB9kmFg8V4JNNsB+s3DDZ0VNEO6LSu1Pssyp5m03EgAA==
X-Received: by 2002:a05:600c:4450:b0:439:9ba1:5f7e with SMTP id 5b1f17b1804b1-43c6020ad16mr8678175e9.21.1741309826782;
        Thu, 06 Mar 2025 17:10:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHVdjk0iePmIcZM7aGxIJsOMmoVTQoIzuivTBOjSzveGw==
Received: by 2002:a05:600c:793:b0:43b:c5a5:513c with SMTP id
 5b1f17b1804b1-43bdb27f344ls5380875e9.1.-pod-prod-02-eu; Thu, 06 Mar 2025
 17:10:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNMNlycAT1alBFLVTb5OUxuxlB/gfINlJq1UWOXLN+c74SpZ8w5r4FdwMRIFA0mJMSlsY/NFmop3c=@googlegroups.com
X-Received: by 2002:a05:600c:1c10:b0:439:9537:e96b with SMTP id 5b1f17b1804b1-43c601cf212mr11748005e9.14.1741309824139;
        Thu, 06 Mar 2025 17:10:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741309824; cv=none;
        d=google.com; s=arc-20240605;
        b=Skj4IO4cawd3Bqg1du3ODhJk27O0fk3rM8mMeUXEM9emlslzJN9jvtAcKuKw04T1E9
         +S8Cdy+VtvkLh/T8X39Fre0xkORp6Ziju18dVePA7uLbL+psvdzXqkx0RGbyreNYDkUZ
         qB620lQzT6oHsCSlSDTsNq1uj7aJN6rJZuWZ+3AIR5m0pWFKf6JB0R8l0yugSdcM+Lyj
         FYWTplIQfWYMG9lpwV2CHA/rAbuTjj4sc5SWEi3UtpErBUtkUEfyf9IIKwRkrU5Vidsb
         um0kgw7ojEOD3SXN3+8y192Tyu8iz9wJwgV49UmciNtUX1LdpgTbjZjynHlmFmqeMczr
         oocw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1wC451i+1YK+YHCL/Lq3MatDtPzBmP7gjobXtW86K/c=;
        fh=SKWR+YHwZthIgaKoxGCFDcqFUpsw/KOciBHf4C3sAjU=;
        b=FUQdEKd/RPb/6kQVOnuc1865dfRxiZ7tXK7q9VFpINlA3aksC0Pom6cOgADtvZYU3C
         /3wKG6DQ/SZtB9nqZZ+nDO6uiHKT0BXcSKnTddwddS9v9rPTdKzycq0217e8BpXi7LOv
         idUclDa36YL3q/dWdq1GawTBzhIJZJKnhuasUni9xD8RgIbQTYo5oELewnZAxz3BZJ2U
         SkO+qUGn4tbVWHAzxjFWHLkY4JQwr+BRodji+azmk7cwVs+XzM9rJUokc6CKzsbqT9U+
         0lngCqiu1g/pvayk5XtQ8xZMSY0izWmeh9Z0lUx4BuHCT9pZO+R8APJVLoPdAaYpljMJ
         q9EQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WXV3Tn/Q";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b167si4099725e9.1.2025.03.06.17.10.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Mar 2025 17:10:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-43bcf9612f4so10889915e9.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Mar 2025 17:10:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVYSCDZtBT7VDmRcseFuX3HutoSsb4EuEpuYVnSEHBlGgyjblxn3uyI4xyCEjjmD9JtloeHMUmwTUc=@googlegroups.com
X-Gm-Gg: ASbGncvlHSalBf1pCZSZQB4UiyafSe3veaS2h/R0HHw2OddgoawSvM8lRIvpGelDHR6
	1Ih3/7wgIaB9NWh9vshFxeIUyGNKxBPgL8xus2Xml1exVNb936a8inBva70Y3TWVKwlg7df6Mum
	VJ5o6ACp/aXA0bGBURo1FHpU7ZWr/U
X-Received: by 2002:a05:6000:1541:b0:390:e62e:f31f with SMTP id
 ffacd0b85a97d-39132d06e74mr961131f8f.3.1741309823366; Thu, 06 Mar 2025
 17:10:23 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
 <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
 <CA+fCnZcCCXPmeEQw0cyQt7MLchMiMvzfZj=g-95UOURT4xK9KQ@mail.gmail.com> <aanh34t7p34xwjc757rzzwraewni54a6xx45q26tljs4crnzbb@s2shobk74gtj>
In-Reply-To: <aanh34t7p34xwjc757rzzwraewni54a6xx45q26tljs4crnzbb@s2shobk74gtj>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 7 Mar 2025 02:10:12 +0100
X-Gm-Features: AQ5f1JqsmdGRGu2uHlQaWnjOnFHn8usJJdOQ1XiECzwCgn8ytUJNZ-8vyFlkmEo
Message-ID: <CA+fCnZdj3_+XPtuq15wbdgLxRqXX+ja6vnPCOx3nfR=Z6Q3ChA@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="WXV3Tn/Q";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Tue, Mar 4, 2025 at 1:31=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> One other question that came to me about how KASAN works, is there some
> mechanism to prevent data races between two threads? In the compiler perh=
aps?
>
> For example memory is de-allocated and shadow memory is poisoned but some=
 other
> thread was just about to do a shadow memory check and was interrupted?
>
> I've read the kasan/vmalloc.c comments and from them I'd extrapolate that=
 the
> caller needs to make sure there are not data races / memory barriers are =
in
> place.

KASAN does nothing to deliberately prevent or detect races. Even if
the race leads to an OOB or UAF, KASAN might not be able to detect it.
But sometimes it does: if poisoned shadow memory values become visible
to the other thread/CPU before it makes a shadow memory value check.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdj3_%2BXPtuq15wbdgLxRqXX%2Bja6vnPCOx3nfR%3DZ6Q3ChA%40mail.gmail.com=
.
