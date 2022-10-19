Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAO4YGNAMGQETLTKZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D10B6605212
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 23:37:05 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9sf14886818eda.19
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 14:37:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666215425; cv=pass;
        d=google.com; s=arc-20160816;
        b=BnJxQS9lO5+FMwSLdmHsFsnPimVQxbeVWhCh8TdisNgZYQyx/YXNrVuSJU1eLdMuJb
         rh1mCA15lE+qAMLWUjDDUb48bGCffgJopZ+/t/Ib6Ge7FF5Xk7i1RRAe9f4+sIh4vVfl
         +NAHhP32cJafUDggwx7uu2WQGaKq8OPFuKdVWU1FETMoigTZKDAjOj3IwCehxGLZJWvV
         +ZqFPD7wekgQ8p25ls9wI7cT8iRRsUTPnVdP/MglQWzaLwMURgVPO09g1Tqcdkb/f6M5
         yZlDdSra9Is/XnHJmAMEXM8GA1mjMtKPVDOoN6iIVHJ4YcS5fc3Yao8WnFUa88PtPyFp
         Diuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GlqN4PxQ1zJeVTm3MD6vNz2TOoUXsxZp+God91ar+mY=;
        b=TMmp3cNOvvSYz6grRlmaWQXhBgRCJQ7wCX/FOUrHnR0t6rxa+wzgOXA2QY4Xkr4MXG
         /gidTeObo0lJxpnptc4ws92Zu/MhRDrNoSS42lO8fG5maevnP/ql7SZE8Y6sop424kA6
         BZrqNBoX0/yGZsBE+P6ayMwQal/rhxi94x0KSipk0PoV6XHin5M4FUXjEsfBrejjKFtl
         Mt+01Y6FAKRC/Vqw0bV3dbNvai9/V3+kmQw3z88qiVpiqsRIr4h0GtkajdbvSc3/D+yU
         gHnfZG71m/82Lh0Qg84c/S+e3o2uWVFJ72aPJbAF9T01EjYQz2jjXKMtAEHSuYYeTy/s
         dnmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kEVsf5yv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GlqN4PxQ1zJeVTm3MD6vNz2TOoUXsxZp+God91ar+mY=;
        b=dyGNrtdwyOPwxp41k/GRA7uBtAN3gQIMxNbn2X+/E2eDvqu9Tr6X7E1g4FYin4ljkj
         XMV+ZHvN9JoXkpsoB+RpyBeJ15VJIJ2bZTdCn5oAWSTE/XUDZ5DB/WF6L2G4MSW6X79t
         Ef3p/rN4apSjbqMlkjx2qBycbLfiI+GYh+FN9curOmo+xmig6s6aRDpahE3XKnesIhtX
         sDXU1jxzeQfu8JBXc/LnWNUbvAv5Tr/GJYbv5BA/AHZkiozrWge9/C2J+lxvCSzZKSLe
         1nl8hmR1gbDCnfz4JdudBF5qj8uDJfZaGNLWT/+wybp3BdhYyjsnlbqjfxfnstkRyyc/
         uOtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GlqN4PxQ1zJeVTm3MD6vNz2TOoUXsxZp+God91ar+mY=;
        b=MS2PSsN60wvpYTQxwjfTKq/BYU/wrKwbcS7N1+zogrY84RqgoSGW/gAclGaQTYtcGk
         zJwcLotnZBNMD5akOgbnzZkk2w/XVzi/a9qLTYjtmVOuD7kfjpu72D3yq5qA6Zm7fxrC
         iWUuE5bZ78RrMupHqJ2kLorpJKMjGgzVzOKQ8Jx2P6yM3nDOAtWChKm9+Ote6xyl3HzC
         IGfDb4xrBpUM/aNkPRF8WrBpp1dmotdsmoWOTu84auvEskavY4b2ISqX3InZUBD+fobE
         tCvaqwyxdPzO/sRe7K2oZHIA0ls7MCG5WYuLR+6ZlOje2u92RyyEqk/uE45rHysc0HhV
         bXuw==
X-Gm-Message-State: ACrzQf2IFPhtKYX+08cO+N8T2AbMt1GWbb0IiWtH6xJgVQ3DVkzQwnpV
	0g55DGF37m1IjRiV5KZnYWY=
X-Google-Smtp-Source: AMsMyM7lCKSugpes8zPauF5BxCFcRsH21vH9LQGNWsm36gbhSIjABNBCLTThkh9QvpeN7DIcy6OvsA==
X-Received: by 2002:a17:906:9be2:b0:78d:957d:9efa with SMTP id de34-20020a1709069be200b0078d957d9efamr8322893ejc.411.1666215425459;
        Wed, 19 Oct 2022 14:37:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1ec1:b0:780:f131:b4d9 with SMTP id
 m1-20020a1709061ec100b00780f131b4d9ls10043345ejj.11.-pod-prod-gmail; Wed, 19
 Oct 2022 14:37:04 -0700 (PDT)
X-Received: by 2002:a17:907:7f05:b0:78d:e869:f2fe with SMTP id qf5-20020a1709077f0500b0078de869f2femr8051124ejc.684.1666215424118;
        Wed, 19 Oct 2022 14:37:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666215424; cv=none;
        d=google.com; s=arc-20160816;
        b=Hxgd89J8PB2Wyv2K2FiXMkrUAYNro5Cc4IqNCDVhSl8eTY/qtP6W2cR8GF1msi/2VY
         WjH/b3wCp8hTG0AH+Qf6A0+mPpRQz+yiSfQAJV9RiHxDVYP7+cNywhZ3vEVB1bplsC0N
         63bKWjCQ6GO7M0DoPjNhWNFUY+WvgSeM5/3OI20j/w640RskoLJ6wIbaTfLtN/RXOu3y
         jsLXD0Zej9GlBrPLmjEKmMuJ5FuFlwDamguDLzlZXPPobSlBmnC1GqfTaWo/AwPN84fG
         N1xmM+ipu4q0ct54BBifuLWKN8LHdsW44fC4ejGiIPD8LvphoztkzpKWuFst8SwxhFHh
         A62Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rQVk2CI7gUTucSPsYsRuO+Xgt/DLnqyh0SKi8lL+BxQ=;
        b=ecmgZorQz6aCcktYfuoMIHtuNI6LTR31Q+mo4W9tPF2kS4iIP8m5x28RebedgYQ6qw
         /scObZt1zF8WMEBiGXOxRCDOovAfV9hF7lk6wQefG3O2IPPQDL0KN5pd5A5SmO8mnX0D
         nZNdWJAyZ3jgyTw7kl6bKRSk3aolyNmDaTplLQRpxAXi2FRFTwpD3muYJySGS536BWgc
         EVsHCFhcX5a6QtOOufMbLrrDrvblf5R6tJClpHAs2R4az2b2ksbBjQTNoXJRWA+NKTIk
         lQ6//B2v61BO9KGQRsqmqIx2u61hwrN2RIBiwGcjhH8YE4mHwsJ5LdetJMyIPEIACPeO
         5GaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kEVsf5yv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id a16-20020aa7cf10000000b004595ce68e4asi671872edy.5.2022.10.19.14.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 14:37:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id j7so31239329wrr.3
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 14:37:04 -0700 (PDT)
X-Received: by 2002:a05:6000:1843:b0:22e:77b0:2e5 with SMTP id c3-20020a056000184300b0022e77b002e5mr6255132wri.215.1666215423700;
        Wed, 19 Oct 2022 14:37:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:b751:df72:2e0f:684c])
        by smtp.gmail.com with ESMTPSA id g7-20020a05600c4ec700b003c409244bb0sm1236729wmq.6.2022.10.19.14.37.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Oct 2022 14:37:02 -0700 (PDT)
Date: Wed, 19 Oct 2022 23:36:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: youling 257 <youling257@gmail.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Biggers <ebiggers@kernel.org>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
Message-ID: <Y1Bt+Ia93mVV/lT3@elver.google.com>
References: <20220915150417.722975-19-glider@google.com>
 <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com>
 <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kEVsf5yv;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Oct 20, 2022 at 04:07AM +0800, youling 257 wrote:
> That is i did,i already test, remove "u64 __tmp=E2=80=A6kmsan_unpoison_me=
mory", no help.
> i only remove kmsan_copy_to_user, fix my issue.

Ok - does only the below work (without the reverts)?

diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index c4cae333deec..eb05caa8f523 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -73,8 +73,8 @@ static inline void kmsan_unpoison_memory(const void *addr=
ess, size_t size)
 static inline void kmsan_check_memory(const void *address, size_t size)
 {
 }
-static inline void kmsan_copy_to_user(void __user *to, const void *from,
-				      size_t to_copy, size_t left)
+static __always_inline void kmsan_copy_to_user(void __user *to, const void=
 *from,
+					       size_t to_copy, size_t left)
 {
 }
=20

... because when you say only removing kmsan_copy_to_user() (from
instrument_put_user()) works, it really doesn't make any sense. The only
explanation would be if the compiler inlining is broken.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y1Bt%2BIa93mVV/lT3%40elver.google.com.
