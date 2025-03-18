Return-Path: <kasan-dev+bncBDW2JDUY5AORB2VD427AMGQEJBLOKXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A3DDFA677DE
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 16:31:56 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5e636b06d34sf3044147a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 08:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742311916; cv=pass;
        d=google.com; s=arc-20240605;
        b=EQF5jp1rFfxd8LTYzW92fOrni6v7tWXzibWpsIXlw1LGBo4Z9Io3Sgr268+zbeTcFt
         AS93Gt9c5OSXb4uWNbUJVR5Tebl+yuu0VMIKHJ3a4+9ZoKd2zJOMvLyCLaxs3Owb4JiU
         3rOx8JJMZSngoBCfEWy0y22adOVU+MC8O/AbccYUoGLB+fKcRq9i4AdBW+tUpQLhv4xs
         jAp+/g2WCXw/FXAtaO719bZZ5JQZ24G1Y9doHuRq+55fijlgMBolsgDHljUx8A52YAwD
         yBYIkAz+R+0NBbxVSwG3EqV05sJSSxr/s4FhF/Fi6D4xPKqT6J2BYZP3xh3/lnlXL4Nr
         90Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=egyncgJsq+i8cluSYEHzzcOnY/iVK7G0nspy8T4C0E8=;
        fh=IIADU3BXxrOzL+9SImrGYxu3d3NLTceM0hU6doYc81U=;
        b=XFwSKWdMz1Fy9RyfLr0Kep+O8WF4Zn6cLOhBgVkiWlgzf3wcScSeGGEU7+CofrIFi+
         AXcl11HAHw5HO9oK+opTdUxOaSkiGhubHupWnxdZC5AYmZsbug89kU+avlhLPXUSzqzc
         zqQB0IaANBANI6NCiRX7GXoxhMBeUbVXCpuiBEGGEdjVjbj2dj+w28Usq7UQXvXDbxOC
         UzvgVfUNOWuKubni5Z+vAUdoAxzUDAFsACdujCo+X/VNBZlU14qA5/Os4ZL/wCnqrOTb
         oHhhjK0mIti76kYgEXVKvCojYjNRuZE3AoHPHvgkfTFqDeqeNtunrMlMBORkdB9X0TWH
         7zzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jZdFVC0O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742311916; x=1742916716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=egyncgJsq+i8cluSYEHzzcOnY/iVK7G0nspy8T4C0E8=;
        b=hCQtqUu/G9VBcY3u/KoQFpqgaq8BBpUtq71QKvWEI5F0KhWS9tyqfLTROW0o7I1iwl
         AA0rBDIqRn5ziWgQhFlY6OjyjN1LYcmp48RlEVN8j5xyJR/IfoyDZ3xe3zKJ46gxhcwR
         ckUfKdUXBxkbsQcR/TGQN8N+zw63o3RGwIvUoV0uXfDkMnAXQisID68JnmV1srerhl45
         /rWhyA7HZaEKoM/ZsFzl64WybzOnRMETI4PZcD5mimHEuHwB+yBevTFoi/9tMozCZm16
         M1dGbsfDoBSzQFKME0emAsMfIfWobPW7KGqDpYA0PqVMisjqAsyphGPpZMzu7Fn0SxgN
         BtFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742311916; x=1742916716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=egyncgJsq+i8cluSYEHzzcOnY/iVK7G0nspy8T4C0E8=;
        b=Uap6XNYBZWwEZ43E0zyiDUPXg7YkUeH3rGtdhGPq/UtOGvi4DX/g6RvJtzfIHg3Xxp
         bHOsqRPPY0p1wm41WNaAe+HwKlpzxUFqfaisykkC2Iq5jusRSaDHRSwCCMHH3/IdHQ0G
         XQ1VesyhkOLHgzCLr5oliFdiiSt0VlXocbtKjP0YWO8EUzo6PbL2RczmK6mNIpbWkkXh
         L75kov/O+0hdIBMiSoYTpga7DeDGURJS0A5xm1xP+Tklq0i2eeVT+3++30nAPxWkhxyD
         k/7RcyerVOrCzR6UCKnAWSdiyLIx0OZXVmjOeSzcRLymDtAKy/HP9LXTwkjqqUu3zFuJ
         IQfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742311916; x=1742916716;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=egyncgJsq+i8cluSYEHzzcOnY/iVK7G0nspy8T4C0E8=;
        b=DMVH2v7ByYguusDSefGZ2F54jwY73QPxpt0eQMk53fCMlSuebmA6CG1GKsz1Z58slM
         g+9ZOnkqZvd1ilmPDEdMagStLGLBcs8+sUmpuEJ9PIlB0sDMrog1HY3xUgUpuRxQES91
         8ug1EaYwbTHTsgpLKAaALbQWdTjVxrRob83nJ561HJNtOdWq3Uwgui9tUxK9gW03ptpO
         ijhj/5Usve/JofVdlx4ITNqcC5A16aUVblkW16bLuqsS5tm4b9AzmKzjxv987wo4UHhw
         1N/qWAhy7Tc1sQrt6Qvy4PjweAjgQFId5TMnMyr+iUvADQaL2n/ODjOBrMrqkeL3dtFJ
         igrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUM7Wg2z4xj5PBnVNKi0YPuc1abRl5fUtfiaizFPDrprEI6eGVo78xvMEC7ZEvjC+zWW3PLw==@lfdr.de
X-Gm-Message-State: AOJu0Yxm35TaY9CERxjEzVs+FUkF1f9hOQkD1UVpjwcGk2XPTd/njbML
	4vR+0PhsKnHXB7hwtSokx0WgOJn72lvmXBnbntHQqcDSyzPg5mje
X-Google-Smtp-Source: AGHT+IExF4A2lQBlSxxredTUIM9p3zCzc+WfgK8NKeUy1iDBGyRoDGgOINTjJSxjTIPGCBDnS34sPQ==
X-Received: by 2002:a05:6402:84f:b0:5e7:dcab:1df8 with SMTP id 4fb4d7f45d1cf-5e8a0426a94mr14230496a12.26.1742311915181;
        Tue, 18 Mar 2025 08:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALMrfhaMHSHSMVsLDD0L6fNdNtFp1C45u96E/14tdUWzg==
Received: by 2002:a50:9513:0:b0:5e7:55b7:3d03 with SMTP id 4fb4d7f45d1cf-5e819e9b088ls153243a12.2.-pod-prod-08-eu;
 Tue, 18 Mar 2025 08:31:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIgOzllyfO0raBab6d7sFcryxtnhE2pMRCNM/6a6k/GICL7CvEOqPeb5EBqkQcy0K0XROgCBth+3U=@googlegroups.com
X-Received: by 2002:a17:906:6a27:b0:ac2:7be7:95c5 with SMTP id a640c23a62f3a-ac3303225c3mr1809172866b.33.1742311912643;
        Tue, 18 Mar 2025 08:31:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742311912; cv=none;
        d=google.com; s=arc-20240605;
        b=CzSJ0co0G1pRhWkqGhF2nXrc1OzVXHScZ8dJfSCc/K7WAEnnlrmDNG4p+kKDHLia+Q
         J9pYFmzBU/YtP5JWKywxMlWH+BHVw1GK+qVFJfeou2G7249FMbdDySygngaC9EJ/wAA5
         c4pbypW9L7JX5DPFDLxepL2LPN2gubJM7iz1l8FXq8gmD+A8zZUh8/7DNbi5ggkx5Gej
         ySsY6IawZxZ4eNpPOYf/z9xSSG6UcaLuFpIVhAVS22pRUu+WfnHCUVYXQptjqc/tq2IA
         Z4+HtFfUgkQDddroJZzMSLC5uTY5CLtXRHEq7a+4YOY23qxl9L2spye4P5/nASCWPDx7
         yCWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CinvE4PqkImlncYqzwGrvxTtdjlYEnx4qMRt+q3DIa0=;
        fh=8LAjPaE9QtQl3t1UYAuPpltnbfaTojp370l7Y0vveWo=;
        b=hd2kNLccoqbzEyc3aHeZcMEB1JREXbF16V8vZnswAfIR4UDxvIPZeqhj35HbAEA4nk
         m2XWxty9vAoIFXeSL/B6LCNmrF2mtpzoZpovoya6McrHrZcEsqjoLxVj5HE4C/eyY40S
         HUJCXX4XzxxH4sCg8rbSH91LRS5iMWg6nac7tn9BKGq2NnEDsXXgMCSmjDnhk+KjCtk6
         nyt5Flt3LhtdSszfmKf5iBXDM57MxynG7xvuSO6wVy05j8U1kUv8zf/4k2RX2bfDJYAd
         Js+aTXsu4c1xKIBbV1TSex/bVXuGFnQMcmML/it0GI7NvvApvL2x+44L0peqoQnrFGhU
         s5Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jZdFVC0O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ac3147e955dsi27764566b.1.2025.03.18.08.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Mar 2025 08:31:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-43cf05f0c3eso26379225e9.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Mar 2025 08:31:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYDEtf/YzIveKLd5REloD0Z+xD9hXGXmLYq6nMwhe3gLfDmPyAekFHLDpUnBXBVuPZfTC+psM43rI=@googlegroups.com
X-Gm-Gg: ASbGncs4Jbjkcalo45hnuGB1pjiLfDXs2aTIpME0M0/gFnq1z/X9XXwTbTJjOK3HgZd
	Duf+Picwc/LW1kb8D90rgofdQus+YVoCevnzkqSJXxHJ1aebooJgD5yh2YK2SGj7jupkmtOeNd/
	xIIRn5fHHiUc9ayyK+6RSLZReTG2w=
X-Received: by 2002:a5d:47cf:0:b0:390:f832:383f with SMTP id
 ffacd0b85a97d-3971d1348b7mr18713568f8f.2.1742311911851; Tue, 18 Mar 2025
 08:31:51 -0700 (PDT)
MIME-Version: 1.0
References: <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
 <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
 <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
 <agqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl@togxtecvtb74>
 <mjyjkyiyhbbxyksiycywgh72laozztzwxxwi3gi252uk4b6f7j@3zwpv7l7aisk>
 <CA+fCnZcDyS8FJwE6x66THExYU_t_n9cTA=9Qy3wL-RSssEb55g@mail.gmail.com>
 <xzxlu4k76wllfreg3oztflyubnmaiktbnvdmszelxxcb4vlhiv@xgo2545uyggy>
 <CA+fCnZdE+rVcoR-sMLdk8e-1Jo_tybOc7PtSp9K6HrP5BEv95g@mail.gmail.com> <qacbgkfbfqylupmoc7umy4n5pdvpdp7hrok7hqefhamhrsnhhm@4e2qucovduw2>
In-Reply-To: <qacbgkfbfqylupmoc7umy4n5pdvpdp7hrok7hqefhamhrsnhhm@4e2qucovduw2>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 18 Mar 2025 16:31:40 +0100
X-Gm-Features: AQ5f1JqGFWmofpIZGo_iwNyrZk8kRGYUZ2Wq3IlRJd5hdIOL8VoWslIcfmDgzvQ
Message-ID: <CA+fCnZfwcV40i_78qY1WTdJc5PgRfvu-_7LERfJyPt6Xf8Ln9Q@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jZdFVC0O;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
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

On Thu, Mar 13, 2025 at 3:58=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >So this was my brain converting things to assembly. Feel free to
> >reword/clarify the comments.
>
> Right, I focused too much on the signed aspect. Treating everything as
> overflowing sounds better, more unified.

Alright!

> >It could be that your checks are equivalent to mine. What I did was to
> >check that the address lies outside of both contiguous regions, which
> >makes the checks symmetrical and IMO easier to follow.
>
> I drew this out and yeah, it looks like it's the same, just grouping the =
logical
> expressions differently. What do you think about incorporating something =
like
> the following into your comment about the x86 part? :
>
>         Given the KASAN_SHADOW_OFFSET equal 0xffeffc0000000000
>         the following ranges are valid mem-to-shadow mappings:
>
>         0xFFFFFFFFFFFFFFFF
>                 INVALID
>         0xFFEFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL)
>                 VALID   - kasan shadow mem
>                 VALID   - non-canonical kernel virtual address
>         0xFFCFFC0000000000 - kasan_mem_to_shadow(0xFEUL << 56)
>                 INVALID
>         0x07EFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL >> 1)
>                 VALID   - non-canonical user virtual addresses
>                 VALID   - user addresses
>         0x07CFFC0000000000 - kasan_mem_to_shadow(0x7EUL << 56)
>                 INVALID
>         0x0000000000000000

Sounds good - I like this visual representation a lot! Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfwcV40i_78qY1WTdJc5PgRfvu-_7LERfJyPt6Xf8Ln9Q%40mail.gmail.com.
