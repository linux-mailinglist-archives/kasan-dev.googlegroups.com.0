Return-Path: <kasan-dev+bncBAABBHNIX3FQMGQEFPH3LAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0NmPDA2hb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBHNIX3FQMGQEFPH3LAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:36:45 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BEEED4631C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:36:44 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-8c530da0691sf1179595785a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:36:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923403; cv=pass;
        d=google.com; s=arc-20240605;
        b=DkeHmDtADcv0CgjzoDoBjfuZAMI9A47N1m4+v5wmdLx98c5az+9qjiCDeE8PZ7eNpT
         HMuu2x/vxqcHA6vK27rn7D8BMre6SyU8NDt58/YQv2mpTvxarZI1zhRNyxZbybRRQy/A
         W8X4PgKzumqMHu35NAQmvYi2Q3QTey949FoVGbwlRcFehQ2/vlVnreVOIkvEM8RnUpX0
         tQJOh6qHRO9vtch3NN1xlUHSVZkKjLfNgCoY/bB/9SU32nNmAwXHGquaovMdoZ8Sgaeu
         syKPPp4VfojbLC4urIKfIlfMo6lIrYkhj5op0BoLd3XLVJJJ/XqcwQZAFbAp0NtXIAjE
         RHhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=HyXVh9lUhCvpPFESgP/Q/JfF6MPJZYJopii+gWzEWig=;
        fh=/Q+2SSLzMPVg4aT60M+yjT/z4iYGkiNsq0uFpiFkUTQ=;
        b=Qc4NtspKlHVqxLI72v3F/W/z5NtGtmIN0D0xQseElNcwOSsTP3i4UZDddA1MDBEMBh
         dDlRGYNlDHNBqdUbx4sa28JpJBS4ss0BLrsLz/o3MMuWvsg+IPmexewk6lJGooDz57WB
         ONYBA+6xlxEK1MCxDQDYI3THsBxRwmce6T2MPQZog2R8hoBukePd8yBTp5yh3Vq3UEyU
         dQo1YVMCx4oHw9/CxIFnPtdtwZML0hgn+RB7y4uGN/235+/+SOzMCFenk6Ek52BVjyQX
         m0Nm1xZ8pVagWRMOk2hP77uIRcjKsTSDcdjDZwhhjD4hl6Mg626knFQ3ZaOVsetVhcUY
         FL8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PmYwNYnj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923403; x=1769528203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=HyXVh9lUhCvpPFESgP/Q/JfF6MPJZYJopii+gWzEWig=;
        b=vsH3ftIDFU6cv2UEQL7TWCt3WAr81Jm0/+K97daqJZucZZkK8RPodr99XgW/ie53Zd
         gVyB1RVDP0ESVmcEjOvYkgf8BcS9amQl04nEXHH5neuhiyWOfwYnNiOz/ary3sZPts4I
         CQRhEbQdOU7S3VyUT8A9BEiJSgytf1kMe/votVgH6cC/LelcrSJKqOsasaLbC09DWFT1
         Q3FhNtp59xBNPgurNbcU2IYTLRKbV+UdeuIOCekGoG17j3FriJdANcekgcFcUvTq3BBw
         +wQrhpaQg+7nQgFfTI86q+i6bg94YHNtULmLb+JcZ0b78676a9LtyWwQP/gUD7ECJPPS
         0n1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923403; x=1769528203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HyXVh9lUhCvpPFESgP/Q/JfF6MPJZYJopii+gWzEWig=;
        b=Xv1Q9JHigpLPgqB+XtGBes6pSTD/nl3WykGtVVo56hwdiyYoyT1L7ar7PlaFNiJ0nA
         gG4y57jNKrQqGxaB//PPa77hk6K8Y6UpnTmbPbI8p+mLOfaalyRR2KlMOwUgQ9MyQ5c3
         Qan4eYI89BWUd8yj2txsDZpN2WNQGJJrThdBpEIS6UiVuxVHfOVgotYcaO9u7fFz0GoM
         fvu49soaisiE2h0INYQCt2d06PyYswh/ERswQSF/9VWzBuYp9pEZP5StWkYwnZM30axG
         2sfVw+IXGEq0Y+hoFX1KFxwd4tsBTQ2mjP9xVpAJyKTpa0VjY4AO7sEUk1H0xVmsx4JU
         8Ntg==
X-Forwarded-Encrypted: i=2; AJvYcCWtKdzSfW8QyVLResQxB22OS2bm/mFhMd4+IDQAZPO8I2DKuecY141Ubu5gli7swQgr4uylcA==@lfdr.de
X-Gm-Message-State: AOJu0YwTz72XX/zrJN+ko7+mjTtRADPagJEnZaijvdVaDavGZclmd9Az
	6ixrok8bjKRD93W8U37iFy53nRLetPGYCOUjOrHwHfLJcCdqBEA8Kb0K
X-Received: by 2002:ac8:6e86:0:b0:4ff:c61a:c8a5 with SMTP id d75a77b69052e-502c2418864mr60907001cf.49.1768920094156;
        Tue, 20 Jan 2026 06:41:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EXdPSNv4qKnM3+iJSCk3uqZrStCsraU1ew+WQdAR6Dpw=="
Received: by 2002:a05:622a:91:b0:501:47f4:eaf7 with SMTP id
 d75a77b69052e-50214a1714als94780211cf.2.-pod-prod-05-us; Tue, 20 Jan 2026
 06:41:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU07nXUqdvkm87sU26IgZXiKmx+ORoH7F1FwQ0/au25kgGyBx3nNSMZPMKhA7G7P2IsauSfob+enPk=@googlegroups.com
X-Received: by 2002:ac8:5e11:0:b0:4f1:abf2:54cb with SMTP id d75a77b69052e-502a1f0dbf2mr219095741cf.43.1768920093131;
        Tue, 20 Jan 2026 06:41:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920093; cv=none;
        d=google.com; s=arc-20240605;
        b=L4dYhn/O/h7c+0pEJO0dax+8BWEfzPj+rrXZGWZKjowWjBmI2zJ+WG/uRS98oDjKME
         1B1q3k1xxiFNYU85lNzDwnDK68B93cDSO/nuu4IEt9kPLHPEWKC46CEdaR9MXQ1gQPXc
         oqTg6x5c3z7R8rGB53SCUfRGE5ghJV10DajJM9PfZUU4utCqSx6ddhExeQQGNlsgwCq6
         maSrGYJCqufLVImQGEfctoNyr1Rlu3KK4fuSdTA2npDkgFSd8SE2/Ug40WgHemMFrMO0
         jyG34skCsYUrqcD9TwR56azc/IGAYLYD4r4Cll0ne0aRCh2gbOgFoSHWJi0MnjW+x9yt
         LkUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=/QCjh1bIysDd4v5OZ14LNkObiBtwfe/ruaYSf4e0H0s=;
        fh=cJFRJAATeg/CzR8znQhyPKClal+KVdtfWdbjznT5Qz4=;
        b=fl11hudpY5rMMspCwAbEppfAZOGPYyeGF5RGdjw3KUmEAB3cZJORh3kPTnUD2HOvZT
         GANw0/5NReUplqRWMQxuo1VXZjgzNtRgkkRdfZsTxsICRmaIxl7+mnFwJs8rWfZcYcMp
         PfW4olSeFiFDIf4uXQoLToD47g0fuQ5EK+EV/NhqZZOgkFTqJAYyH/o9qnuxfbOnl2Vl
         JHPN7F4mPvGgvPq/r2zUKTVoijbR1rKr4mxH0xEuXyIM5e0E9Dhsls0lyqpoZ0R6TVDQ
         NuyZWOXOAQ9wxOF/xzFih1WrVUrg7vlHx+nUPTaluHwto3809wHSKO/HgQBHV2ISxCJv
         Y0ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PmYwNYnj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1e340acsi3952881cf.3.2026.01.20.06.41.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:41:33 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Tue, 20 Jan 2026 14:41:25 +0000
To: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nsc@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: [PATCH v9 03/13] kasan: Fix inline mode for x86 tag-based mode
Message-ID: <afb50f5db054f807b57f33f591fc43d79862e9a2.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: a28f2f4e8684592b68d763d58d259d63cccf2fce
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=PmYwNYnj;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBHNIX3FQMGQEFPH3LAI];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,google.com,arm.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,pm.me:mid,pm.me:replyto,intel.com:email,mail-qk1-x739.google.com:rdns,mail-qk1-x739.google.com:helo]
X-Rspamd-Queue-Id: BEEED4631C
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
Changelog v9:
- Add Andrey Ryabinin's Reviewed-by tag.

Changelog v7:
- Add Alexander's Reviewed-by tag.

Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 0ba2aac3b8dc..e485814df3e9 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/afb50f5db054f807b57f33f591fc43d79862e9a2.1768845098.git.m.wieczorretman%40pm.me.
