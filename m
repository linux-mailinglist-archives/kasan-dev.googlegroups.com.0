Return-Path: <kasan-dev+bncBDV2D5O34IDRBX522DXAKGQEO2K74HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 77DB51029CC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:50:43 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id v71sf10044325vkd.16
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 08:50:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574182241; cv=pass;
        d=google.com; s=arc-20160816;
        b=vmdcm4PIHWmXN+On1z8uVBO3dbCrIwm3dI3C0s3O+W2t3vgBc+oSbD6gNsBF5epGbF
         StX/nEJsKVQidUgdX2uDv5F70FyvsVMM4gNibzYzN1nlkyOgmq0Hmpwy1GM1cOSWhgdj
         TNI3HW8UZ3fQAG2IAs6zIVjwZBXRx/KEUE9XN1jEqbyTMYfvhPdGDxfyhtzvp6sfbDbN
         v3hcC+B8BnLrnCqcW2DLg77kCs3CG7Q7JyJRlntfelPM/okLiNJOddlKfBgr2kFAVNuC
         /152EC98ePw8lKMa1HWc3dh+++3gtGjNkv2hHG/XLkvcJNoL+WV0jpg9dgx+nWXKkaqT
         6wdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3s1xgOJQhHqL4ZsLrNntkTnkMaBCezVLPcz+eZJKfrM=;
        b=bqNzn0/nbsn7d9PzosU7ht2BgeyhA8Jcj0A+FTO/5/2fZf+XGosBwWnL3q55COEqLX
         1oc1dvlgFBbWqB6vYlj+15iiIbfgN3qkIliky4RO8ln3Q55mjTugwv/4nMiMsxcHaiQh
         uJQ7FdpQFexN1fBQIf//0Y6Ub1gKu3HXVs0wLpHBRxt4JOKUOJdToUbuQav+hcPVF9Bx
         yCK+LpXoNmrdHoYm9GxL5UnI3w8FcNddqeVLswstghHHE/3gA8DfmjD7Nbc8PrcVs/D6
         Mi7XPhAehLhoDVdpM5J13mHkFAPZCE0hWLI/SkFdefNwexJoQui2X0SEez1gcRYWK/Tm
         1iXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="js/jpGBu";
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3s1xgOJQhHqL4ZsLrNntkTnkMaBCezVLPcz+eZJKfrM=;
        b=Ey0QiKG+K656jRSSWJJNpaNQQKxHT0YGvCgNRSDR9L+aJh9q0uD36TZyE58H+RuyH3
         9luhMTIXEO2iWC2GMJtdWkO47/kA+qqwp5HLX/oDAfS+IbDn1QRrfO2XOA1W3Igq4+Mt
         jkW6mLrhIdDBj/V2NBrmG4cSJSWHBztNlEEiLLfayCS1vwq5RPK5ovNY6l0e23etCEOl
         mzy9++HxuTCui4/PUTz58QCtgbgnELLXzapIzRdjnGg2y2+8XXsVxzBD+8V7KxwNjHLJ
         y0Y/f82MLrohNz9YDNuEXtmsb2yeTF2d/lSqnJeRU2gdKX4fpJ2GYm9F+HhJYT7OuGdn
         wBuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3s1xgOJQhHqL4ZsLrNntkTnkMaBCezVLPcz+eZJKfrM=;
        b=czAGAxNUqCfbRlZ5ljn6RtB5XmAM9wejVTvfnZk8RKic2W0lECaxAglMTn9FIIRjkI
         4+pEn44Ol9GVS8Kxar0/GYy5BjxnWYTF5dHfrzfU4ZHA6P65YAT3HHS9wqY0EomJEB0n
         F7cb7LPxdVhYJ9UvuWz6pzuzt+dwOGmIESawSzWqPAt5qTFX3bDxnFEMqQAhgGiwF6i4
         UnH/SFZXYIfVXCCS+9/HwruCTigQPYHdRt4Dd6L/QhiCvMUE5IOBOtjRUskNxtlA+rpK
         CGLx4pg9nv3V51j7bbcBQlox8BgRGMVvItBY1l/U7yap/V0ZamzRVYwmpdLQUBH/2FP5
         AJPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXnpjbuHnO3O3W7JlrlIf9kGgCr+++LiIZDnAroeiOnAZo1YmCQ
	MvPEymshR2zqFWEPIBE+M3k=
X-Google-Smtp-Source: APXvYqxr6Rdh4hyDDT+IZp+t1966Ntb+UdgomqdK7dYNa/htRTwEolhJzHR+xuQlC/WiWM4Uew0QJQ==
X-Received: by 2002:a67:6e05:: with SMTP id j5mr22753856vsc.66.1574182239046;
        Tue, 19 Nov 2019 08:50:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd05:: with SMTP id y5ls2761863vsj.16.gmail; Tue, 19 Nov
 2019 08:50:38 -0800 (PST)
X-Received: by 2002:a67:ca18:: with SMTP id z24mr9189647vsk.38.1574182238606;
        Tue, 19 Nov 2019 08:50:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574182238; cv=none;
        d=google.com; s=arc-20160816;
        b=hFrg6XjfUZfzrywHhIiT77AIRbkZWAJSA5M4lgC7SlOYqRG9CYgxfnk9y8h+toQrtb
         xfm3R04B0enT0L4et2rIKCfxeswyoaQ1FFBZ69NysDkc7cRI0QQKIHROVWo4RpbMVT6G
         W2JVNtzsp8/ymQulfiDJi23Nmyr3WL6dUluKQkr67mZamTsMmxgMYnCYoV538JyOMeph
         u7KXJpuRg81fG8HjMoCIA4yhSZEVBXbgx2rb7xIylwsYMzcPUVH738wti+AfLAezECYu
         zNdxgp5nBqef1QPcrssihXi0F2mH9p85wPVx8LmI89gpa0XjdnpE4d9VGpUCzlh0RPap
         q2BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:dkim-signature;
        bh=Xn6iNiPfZCWOiCQrXg5+CWjzBzTZW6/v84MCabjACgU=;
        b=RPKBsOWbk8+k78duS1Rcq4x/LvG2CoXCfTQSajTczwqXbyKmBD+/Z7AUkaYdlt0TiH
         eMCzPQz5BKBogTMAc3utMase+vaDRsMYAP1meXMzo4DjCUFHZeXAMpzBFDGndhLgxdhT
         LRoKWi8ifiXLUlCO72yDCQACjURNNi5c+rSNkPJti8lZJS3WTTN50rgB6bVqOoqVzeJM
         NG847Lvn/n1CZQtPIAC8SIkYrYwLSp+rnaNC8cqBdAcQwEmun13ZPt0Wm0/56N2m5xsj
         HTWDAkOd15GU9t2jSSX9e9sCkeMxXWrovkwh9yYF8HVPtl/5ekfKug+DxCvyggZ1pegV
         HSYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="js/jpGBu";
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id u17si753763vsn.0.2019.11.19.08.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 08:50:38 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::5a22]
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iX6i3-0007dz-HK; Tue, 19 Nov 2019 16:50:36 +0000
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
To: Marco Elver <elver@google.com>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux Next Mailing List <linux-next@vger.kernel.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
Date: Tue, 19 Nov 2019 08:50:34 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
Content-Type: multipart/mixed;
 boundary="------------C7218DDDD46B2547AEB41C50"
Content-Language: en-US
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="js/jpGBu";
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

This is a multi-part message in MIME format.
--------------C7218DDDD46B2547AEB41C50
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On 11/19/19 8:12 AM, Marco Elver wrote:
> On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org> wrote:
>>
>> On 11/19/19 12:46 AM, Stephen Rothwell wrote:
>>> Hi all,
>>>
>>> Changes since 20191118:
>>>
>>
>> on x86_64:
>>
>> It seems that this function can already be known by the compiler as a
>> builtin:
>>
>> ../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in fu=
nction =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]
>>  void __tsan_func_exit(void)
>>       ^~~~~~~~~~~~~~~~
>>
>>
>> $ gcc --version
>> gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]
>=20
> Interesting. Could you share the .config? So far I haven't been able
> to reproduce.

Sure, it's attached.

> I can get the warning if I manually add -fsanitize=3Dthread to flags for
> kcsan/core.c (but normally disabled via KCSAN_SANITIZE :=3D n). If
> possible could you also share the output of `make V=3D1` for
> kcsan/core.c?

here:

make -C /home/rdunlap/lnx/next/linux-next-20191119/xx64 -f /home/rdunlap/ln=
x/next/linux-next-20191119/Makefile kernel/kcsan/core.o
make[1]: Entering directory '/home/rdunlap/lnx/next/linux-next-20191119/xx6=
4'
if [ -f ../.config -o \
	 -d ../include/config -o \
	 -d ../arch/x86/include/generated ]; then \
	echo >&2 "***"; \
	echo >&2 "*** The source tree is not clean, please run 'make ARCH=3Dx86_64=
 mrproper'"; \
	echo >&2 "*** in /home/rdunlap/lnx/next/linux-next-20191119";\
	echo >&2 "***"; \
	false; \
fi
ln -fsn .. source
sh ../scripts/mkmakefile ..
  GEN     Makefile
test -e .gitignore || \
{ echo "# this is build directory, ignore it"; echo "*"; } > .gitignore
make -f ../scripts/Makefile.build obj=3Darch/x86/entry/syscalls all
make -f ../scripts/Makefile.build obj=3Dscripts/basic
rm -f .tmp_quiet_recordmcount
make -f ../scripts/Makefile.build obj=3Darch/x86/tools relocs
make -f ../scripts/Makefile.build obj=3Dscripts/dtc
make -f ../scripts/Makefile.build obj=3Dscripts
make -f ../scripts/Makefile.build obj=3Dscripts/genksyms \
 \
need-builtin=3D \
need-modorder=3D
set -e; mkdir -p include/config/; { echo "5.4.0-rc8$(sh ../scripts/setlocal=
version ..)"; } > include/config/kernel.release.tmp; if [ -r include/config=
/kernel.release ] && cmp -s include/config/kernel.release include/config/ke=
rnel.release.tmp; then rm -f include/config/kernel.release.tmp; else : '  U=
PD     include/config/kernel.release'; mv -f include/config/kernel.release.=
tmp include/config/kernel.release; fi
make -f ../scripts/Makefile.asm-generic obj=3Darch/x86/include/generated/ua=
pi/asm \
generic=3Dinclude/uapi/asm-generic
make -f ../scripts/Makefile.asm-generic obj=3Darch/x86/include/generated/as=
m \
generic=3Dinclude/asm-generic
set -e; mkdir -p include/generated/uapi/linux/; { 	echo \#define LINUX_VERS=
ION_CODE 328704; echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) <<=
 8) + (c))'; } > include/generated/uapi/linux/version.h.tmp; if [ -r includ=
e/generated/uapi/linux/version.h ] && cmp -s include/generated/uapi/linux/v=
ersion.h include/generated/uapi/linux/version.h.tmp; then rm -f include/gen=
erated/uapi/linux/version.h.tmp; else : '  UPD     include/generated/uapi/l=
inux/version.h'; mv -f include/generated/uapi/linux/version.h.tmp include/g=
enerated/uapi/linux/version.h; fi
rm -f include/linux/version.h
set -e; mkdir -p include/generated/; { 	if [ `echo -n "5.4.0-rc8-next-20191=
119" | wc -c ` -gt 64 ]; then echo '"5.4.0-rc8-next-20191119" exceeds 64 ch=
aracters' >&2; exit 1; fi; echo \#define UTS_RELEASE \"5.4.0-rc8-next-20191=
119\"; } > include/generated/utsrelease.h.tmp; if [ -r include/generated/ut=
srelease.h ] && cmp -s include/generated/utsrelease.h include/generated/uts=
release.h.tmp; then rm -f include/generated/utsrelease.h.tmp; else : '  UPD=
     include/generated/utsrelease.h'; mv -f include/generated/utsrelease.h.=
tmp include/generated/utsrelease.h; fi
make -f ../scripts/Makefile.build obj=3Dscripts/mod
  gcc -Wp,-MD,scripts/mod/.empty.o.d  -nostdinc -isystem /usr/lib64/gcc/x86=
_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/include/generat=
ed -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include=
/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../in=
clude/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERNEL=
__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-ali=
asing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-declar=
ation -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse -mn=
o-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=3D=
1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-rax-s=
etup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D1 -=
DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS_SS=
SE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 -DC=
ONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-async=
hronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address -W=
no-format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data-ra=
ces=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-set=
-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-frame=
-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -Wdeclar=
ation-after-statement -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-mer=
ge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werro=
r=3Ddate-time -Werror=3Dincompatible-pointer-types -Werror=3Ddesignated-ini=
t  -fprofile-arcs -ftest-coverage -fno-tree-loop-im -Wno-maybe-uninitialize=
d    -fsanitize=3Dshift  -fsanitize=3Dinteger-divide-by-zero  -fsanitize=3D=
unreachable  -fsanitize=3Dsigned-integer-overflow  -fsanitize=3Dbounds  -fs=
anitize=3Dobject-size  -fsanitize=3Dbool  -fsanitize=3Denum  -Wno-maybe-uni=
nitialized   -fsanitize=3Dthread -I ../scripts/mod -I ./scripts/mod    -DKB=
UILD_BASENAME=3D'"empty"' -DKBUILD_MODNAME=3D'"empty"' -c -o scripts/mod/em=
pty.o ../scripts/mod/empty.c
  sh ../scripts/gen_ksymdeps.sh scripts/mod/empty.o >> scripts/mod/.empty.o=
.cmd
  if objdump -h scripts/mod/empty.o | grep -q __ksymtab; then gcc -E -D__GE=
NKSYMS__ -Wp,-MD,scripts/mod/.empty.o.d  -nostdinc -isystem /usr/lib64/gcc/=
x86_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/include/gene=
rated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/incl=
ude/generated/uapi -I../include/uapi -I./include/generated/uapi -include ..=
/include/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KER=
NEL__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-=
aliasing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-dec=
laration -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse =
-mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=
=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-ra=
x-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D=
1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS=
_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 =
-DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-as=
ynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address=
 -Wno-format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data=
-races=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-=
set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-fr=
ame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -Wdec=
laration-after-statement -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-=
merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -We=
rror=3Ddate-time -Werror=3Dincompatible-pointer-types -Werror=3Ddesignated-=
init  -fprofile-arcs -ftest-coverage -fno-tree-loop-im -Wno-maybe-uninitial=
ized    -fsanitize=3Dshift  -fsanitize=3Dinteger-divide-by-zero  -fsanitize=
=3Dunreachable  -fsanitize=3Dsigned-integer-overflow  -fsanitize=3Dbounds  =
-fsanitize=3Dobject-size  -fsanitize=3Dbool  -fsanitize=3Denum  -Wno-maybe-=
uninitialized   -fsanitize=3Dthread -I ../scripts/mod -I ./scripts/mod    -=
DKBUILD_BASENAME=3D'"empty"' -DKBUILD_MODNAME=3D'"empty"' ../scripts/mod/em=
pty.c | scripts/genksyms/genksyms    -r /dev/null > scripts/mod/.tmp_empty.=
ver; ld -m elf_x86_64  -z max-page-size=3D0x200000 -r -o scripts/mod/.tmp_e=
mpty.o scripts/mod/empty.o -T scripts/mod/.tmp_empty.ver; mv -f scripts/mod=
/.tmp_empty.o scripts/mod/empty.o; rm -f scripts/mod/.tmp_empty.ver; fi
  scripts/mod/mk_elfconfig < scripts/mod/empty.o > scripts/mod/elfconfig.h
  gcc -Wp,-MD,scripts/mod/.modpost.o.d -Wall -Wmissing-prototypes -Wstrict-=
prototypes -O2 -fomit-frame-pointer -std=3Dgnu89       -I ./scripts/mod -c =
-o scripts/mod/modpost.o ../scripts/mod/modpost.c
  gcc -Wp,-MD,scripts/mod/.devicetable-offsets.s.d -nostdinc -isystem /usr/=
lib64/gcc/x86_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/in=
clude/generated -I../include -I./include -I../arch/x86/include/uapi -I./arc=
h/x86/include/generated/uapi -I../include/uapi -I./include/generated/uapi -=
include ../include/linux/kconfig.h -include ../include/linux/compiler_types=
.h -D__KERNEL__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -f=
no-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-fu=
nction-declaration -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89=
 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -fa=
lign-loops=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3=
 -mskip-rax-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG=
_AS_CFI=3D1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -=
DCONFIG_AS_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_A=
VX512=3D1 -DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compa=
re -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-fra=
me-address -Wno-format-truncation -Wno-format-overflow -O2 --param=3Dallow-=
store-data-races=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-u=
nused-but-set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -f=
no-omit-frame-pointer -fno-optimize-sibling-calls -Wdeclaration-after-state=
ment -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-merge-all-constants =
-fmerge-constants -fno-stack-check -fconserve-stack -Werror=3Ddate-time -We=
rror=3Dincompatible-pointer-types -Werror=3Ddesignated-init -fprofile-arcs =
-ftest-coverage -fno-tree-loop-im -Wno-maybe-uninitialized -fsanitize=3Dshi=
ft -fsanitize=3Dinteger-divide-by-zero -fsanitize=3Dunreachable -fsanitize=
=3Dsigned-integer-overflow -fsanitize=3Dbounds -fsanitize=3Dobject-size -fs=
anitize=3Dbool -fsanitize=3Denum -Wno-maybe-uninitialized -fsanitize=3Dthre=
ad -I ../scripts/mod -I ./scripts/mod -DKBUILD_BASENAME=3D'"devicetable_off=
sets"' -DKBUILD_MODNAME=3D'"devicetable_offsets"'  -fverbose-asm -S -o scri=
pts/mod/devicetable-offsets.s ../scripts/mod/devicetable-offsets.c
set -e; mkdir -p scripts/mod/; { 	 echo "#ifndef __DEVICETABLE_OFFSETS_H__"=
; echo "#define __DEVICETABLE_OFFSETS_H__"; echo "/*"; echo " * DO NOT MODI=
FY."; echo " *"; echo " * This file was generated by Kbuild"; echo " */"; e=
cho ""; sed -ne 	's:^[[:space:]]*\.ascii[[:space:]]*"\(.*\)".*:\1:; /^->/{s=
:->#\(.*\):/* \1 */:; s:^->\([^ ]*\) [\$#]*\([^ ]*\) \(.*\):#define \1 \2 /=
* \3 */:; s:->::; p;}' < scripts/mod/devicetable-offsets.s; echo ""; echo "=
#endif"; } > scripts/mod/devicetable-offsets.h.tmp; if [ -r scripts/mod/dev=
icetable-offsets.h ] && cmp -s scripts/mod/devicetable-offsets.h scripts/mo=
d/devicetable-offsets.h.tmp; then rm -f scripts/mod/devicetable-offsets.h.t=
mp; else : '  UPD     scripts/mod/devicetable-offsets.h'; mv -f scripts/mod=
/devicetable-offsets.h.tmp scripts/mod/devicetable-offsets.h; fi
  gcc -Wp,-MD,scripts/mod/.file2alias.o.d -Wall -Wmissing-prototypes -Wstri=
ct-prototypes -O2 -fomit-frame-pointer -std=3Dgnu89       -I ./scripts/mod =
-c -o scripts/mod/file2alias.o ../scripts/mod/file2alias.c
  gcc -Wp,-MD,scripts/mod/.sumversion.o.d -Wall -Wmissing-prototypes -Wstri=
ct-prototypes -O2 -fomit-frame-pointer -std=3Dgnu89       -I ./scripts/mod =
-c -o scripts/mod/sumversion.o ../scripts/mod/sumversion.c
  gcc   -o scripts/mod/modpost scripts/mod/modpost.o scripts/mod/file2alias=
.o scripts/mod/sumversion.o  =20
make -f ../scripts/Makefile.build obj=3D.
  gcc -Wp,-MD,kernel/.bounds.s.d -nostdinc -isystem /usr/lib64/gcc/x86_64-s=
use-linux/7/include -I../arch/x86/include -I./arch/x86/include/generated -I=
../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include/gene=
rated/uapi -I../include/uapi -I./include/generated/uapi -include ../include=
/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERNEL__ -W=
all -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-aliasing=
 -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-declaration=
 -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse -mno-mmx=
 -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=3D1 -mn=
o-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-rax-setup =
-mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D1 -DCONF=
IG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS_SSSE3=
=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 -DCONF=
IG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-asynchro=
nous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-=
format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data-races=
=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-set-va=
riable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-frame-po=
inter -fno-optimize-sibling-calls -Wdeclaration-after-statement -Wvla -Wno-=
pointer-sign -fno-strict-overflow -fno-merge-all-constants -fmerge-constant=
s -fno-stack-check -fconserve-stack -Werror=3Ddate-time -Werror=3Dincompati=
ble-pointer-types -Werror=3Ddesignated-init -fprofile-arcs -ftest-coverage =
-fno-tree-loop-im -Wno-maybe-uninitialized -fsanitize=3Dshift -fsanitize=3D=
integer-divide-by-zero -fsanitize=3Dunreachable -fsanitize=3Dsigned-integer=
-overflow -fsanitize=3Dbounds -fsanitize=3Dobject-size -fsanitize=3Dbool -f=
sanitize=3Denum -Wno-maybe-uninitialized -fsanitize=3Dthread -I ../. -I ./.=
 -DKBUILD_BASENAME=3D'"bounds"' -DKBUILD_MODNAME=3D'"bounds"'  -fverbose-as=
m -S -o kernel/bounds.s ../kernel/bounds.c
set -e; mkdir -p include/generated/; { 	 echo "#ifndef __LINUX_BOUNDS_H__";=
 echo "#define __LINUX_BOUNDS_H__"; echo "/*"; echo " * DO NOT MODIFY."; ec=
ho " *"; echo " * This file was generated by Kbuild"; echo " */"; echo ""; =
sed -ne 	's:^[[:space:]]*\.ascii[[:space:]]*"\(.*\)".*:\1:; /^->/{s:->#\(.*=
\):/* \1 */:; s:^->\([^ ]*\) [\$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:=
; s:->::; p;}' < kernel/bounds.s; echo ""; echo "#endif"; } > include/gener=
ated/bounds.h.tmp; if [ -r include/generated/bounds.h ] && cmp -s include/g=
enerated/bounds.h include/generated/bounds.h.tmp; then rm -f include/genera=
ted/bounds.h.tmp; else : '  UPD     include/generated/bounds.h'; mv -f incl=
ude/generated/bounds.h.tmp include/generated/bounds.h; fi
set -e; mkdir -p include/generated/; { echo 1000 | bc -q ../kernel/time/tim=
econst.bc; } > include/generated/timeconst.h.tmp; if [ -r include/generated=
/timeconst.h ] && cmp -s include/generated/timeconst.h include/generated/ti=
meconst.h.tmp; then rm -f include/generated/timeconst.h.tmp; else : '  UPD =
    include/generated/timeconst.h'; mv -f include/generated/timeconst.h.tmp=
 include/generated/timeconst.h; fi
  gcc -Wp,-MD,arch/x86/kernel/.asm-offsets.s.d -nostdinc -isystem /usr/lib6=
4/gcc/x86_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/includ=
e/generated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x8=
6/include/generated/uapi -I../include/uapi -I./include/generated/uapi -incl=
ude ../include/linux/kconfig.h -include ../include/linux/compiler_types.h -=
D__KERNEL__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-s=
trict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-functi=
on-declaration -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mn=
o-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign=
-loops=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -ms=
kip-rax-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_=
CFI=3D1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCON=
FIG_AS_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX51=
2=3D1 -DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -=
fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-a=
ddress -Wno-format-truncation -Wno-format-overflow -O2 --param=3Dallow-stor=
e-data-races=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unuse=
d-but-set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-o=
mit-frame-pointer -fno-optimize-sibling-calls -Wdeclaration-after-statement=
 -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-merge-all-constants -fme=
rge-constants -fno-stack-check -fconserve-stack -Werror=3Ddate-time -Werror=
=3Dincompatible-pointer-types -Werror=3Ddesignated-init -fprofile-arcs -fte=
st-coverage -fno-tree-loop-im -Wno-maybe-uninitialized -fsanitize=3Dshift -=
fsanitize=3Dinteger-divide-by-zero -fsanitize=3Dunreachable -fsanitize=3Dsi=
gned-integer-overflow -fsanitize=3Dbounds -fsanitize=3Dobject-size -fsaniti=
ze=3Dbool -fsanitize=3Denum -Wno-maybe-uninitialized -fsanitize=3Dthread -I=
 ../. -I ./. -DKBUILD_BASENAME=3D'"asm_offsets"' -DKBUILD_MODNAME=3D'"asm_o=
ffsets"'  -fverbose-asm -S -o arch/x86/kernel/asm-offsets.s ../arch/x86/ker=
nel/asm-offsets.c
set -e; mkdir -p include/generated/; { 	 echo "#ifndef __ASM_OFFSETS_H__"; =
echo "#define __ASM_OFFSETS_H__"; echo "/*"; echo " * DO NOT MODIFY."; echo=
 " *"; echo " * This file was generated by Kbuild"; echo " */"; echo ""; se=
d -ne 	's:^[[:space:]]*\.ascii[[:space:]]*"\(.*\)".*:\1:; /^->/{s:->#\(.*\)=
:/* \1 */:; s:^->\([^ ]*\) [\$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; =
s:->::; p;}' < arch/x86/kernel/asm-offsets.s; echo ""; echo "#endif"; } > i=
nclude/generated/asm-offsets.h.tmp; if [ -r include/generated/asm-offsets.h=
 ] && cmp -s include/generated/asm-offsets.h include/generated/asm-offsets.=
h.tmp; then rm -f include/generated/asm-offsets.h.tmp; else : '  UPD     in=
clude/generated/asm-offsets.h'; mv -f include/generated/asm-offsets.h.tmp i=
nclude/generated/asm-offsets.h; fi
  sh ../scripts/checksyscalls.sh gcc -Wp,-MD,./.missing-syscalls.d  -nostdi=
nc -isystem /usr/lib64/gcc/x86_64-suse-linux/7/include -I../arch/x86/includ=
e -I./arch/x86/include/generated -I../include -I./include -I../arch/x86/inc=
lude/uapi -I./arch/x86/include/generated/uapi -I../include/uapi -I./include=
/generated/uapi -include ../include/linux/kconfig.h -include ../include/lin=
ux/compiler_types.h -D__KERNEL__ -Wall -Wundef -Werror=3Dstrict-prototypes =
-Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Wer=
ror=3Dimplicit-function-declaration -Werror=3Dimplicit-int -Wno-format-secu=
rity -std=3Dgnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -fal=
ign-jumps=3D1 -falign-loops=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-s=
tack-boundary=3D3 -mskip-rax-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=
=3Dkernel -DCONFIG_AS_CFI=3D1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_=
CFI_SECTIONS=3D1 -DCONFIG_AS_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=
=3D1 -DCONFIG_AS_AVX512=3D1 -DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=
=3D1 -Wno-sign-compare -fno-asynchronous-unwind-tables -fno-delete-null-poi=
nter-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow =
-O2 --param=3Dallow-store-data-races=3D0 -Wframe-larger-than=3D2048 -fno-st=
ack-protector -Wno-unused-but-set-variable -Wimplicit-fallthrough -Wno-unus=
ed-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-=
var-tracking-assignments -Wdeclaration-after-statement -Wvla -Wno-pointer-s=
ign -fno-strict-overflow -fno-merge-all-constants -fmerge-constants -fno-st=
ack-check -fconserve-stack -Werror=3Ddate-time -Werror=3Dincompatible-point=
er-types -Werror=3Ddesignated-init  -fprofile-arcs -ftest-coverage -fno-tre=
e-loop-im -Wno-maybe-uninitialized    -fsanitize=3Dshift  -fsanitize=3Dinte=
ger-divide-by-zero  -fsanitize=3Dunreachable  -fsanitize=3Dsigned-integer-o=
verflow  -fsanitize=3Dbounds  -fsanitize=3Dobject-size  -fsanitize=3Dbool  =
-fsanitize=3Denum  -Wno-maybe-uninitialized   -fsanitize=3Dthread -I ../. -=
I ./.    -DKBUILD_BASENAME=3D'"missing_syscalls"' -DKBUILD_MODNAME=3D'"miss=
ing_syscalls"'=20
  sh ../scripts/atomic/check-atomics.sh
make -f ../scripts/Makefile.build obj=3Dscripts scripts/unifdef
make -f ../scripts/Makefile.headersinst obj=3Dinclude/uapi
make -f ../scripts/Makefile.headersinst obj=3Darch/x86/include/uapi
make -f ../scripts/Makefile.build obj=3Dinit single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dusr single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Darch/x86 single-build=3D1 need-buil=
tin=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dkernel single-build=3D1 need-builti=
n=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dkernel/kcsan \
 \
need-builtin=3D1 \
need-modorder=3D1
  gcc -Wp,-MD,kernel/kcsan/.core.o.d  -nostdinc -isystem /usr/lib64/gcc/x86=
_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/include/generat=
ed -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include=
/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../in=
clude/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERNEL=
__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-ali=
asing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-declar=
ation -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse -mn=
o-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=3D=
1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-rax-s=
etup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D1 -=
DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS_SS=
SE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 -DC=
ONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-async=
hronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address -W=
no-format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data-ra=
ces=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-set=
-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-frame=
-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -Wdeclar=
ation-after-statement -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-mer=
ge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werro=
r=3Ddate-time -Werror=3Dincompatible-pointer-types -Werror=3Ddesignated-ini=
t -fno-conserve-stack -fno-stack-protector  -fprofile-arcs -ftest-coverage =
-fno-tree-loop-im -Wno-maybe-uninitialized    -fsanitize=3Dshift  -fsanitiz=
e=3Dinteger-divide-by-zero  -fsanitize=3Dunreachable  -fsanitize=3Dsigned-i=
nteger-overflow  -fsanitize=3Dbounds  -fsanitize=3Dobject-size  -fsanitize=
=3Dbool  -fsanitize=3Denum  -Wno-maybe-uninitialized   -I ../kernel/kcsan -=
I ./kernel/kcsan    -DKBUILD_BASENAME=3D'"core"' -DKBUILD_MODNAME=3D'"core"=
' -c -o kernel/kcsan/core.o ../kernel/kcsan/core.c
../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in funct=
ion =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]
 void __tsan_func_exit(void)
      ^~~~~~~~~~~~~~~~
In file included from ../include/linux/linkage.h:7:0,
                 from ../include/linux/kernel.h:8,
                 from ../include/asm-generic/bug.h:19,
                 from ../arch/x86/include/asm/bug.h:83,
                 from ../include/linux/bug.h:5,
                 from ../kernel/kcsan/core.c:4:
../kernel/kcsan/core.c:622:15: warning: conflicting types for built-in func=
tion =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]
 EXPORT_SYMBOL(__tsan_func_exit);
               ^
../include/linux/export.h:87:21: note: in definition of macro =E2=80=98___E=
XPORT_SYMBOL=E2=80=99
  extern typeof(sym) sym;      \
                     ^~~
../include/linux/export.h:128:2: note: in expansion of macro =E2=80=98__con=
d_export_sym_1=E2=80=99
  __cond_export_sym_##enabled(sym, sec, ns)
  ^~~~~~~~~~~~~~~~~~
../include/linux/export.h:126:2: note: in expansion of macro =E2=80=98___co=
nd_export_sym=E2=80=99
  ___cond_export_sym(sym, sec, ns, conf)
  ^~~~~~~~~~~~~~~~~~
../include/linux/export.h:124:2: note: in expansion of macro =E2=80=98__con=
d_export_sym=E2=80=99
  __cond_export_sym(sym, sec, ns, __is_defined(__KSYM_##sym))
  ^~~~~~~~~~~~~~~~~
../include/linux/export.h:142:34: note: in expansion of macro =E2=80=98__EX=
PORT_SYMBOL=E2=80=99
 #define _EXPORT_SYMBOL(sym, sec) __EXPORT_SYMBOL(sym, sec, "")
                                  ^~~~~~~~~~~~~~~
../include/linux/export.h:145:29: note: in expansion of macro =E2=80=98_EXP=
ORT_SYMBOL=E2=80=99
 #define EXPORT_SYMBOL(sym)  _EXPORT_SYMBOL(sym, "")
                             ^~~~~~~~~~~~~~
../kernel/kcsan/core.c:622:1: note: in expansion of macro =E2=80=98EXPORT_S=
YMBOL=E2=80=99
 EXPORT_SYMBOL(__tsan_func_exit);
 ^~~~~~~~~~~~~
  sh ../scripts/gen_ksymdeps.sh kernel/kcsan/core.o >> kernel/kcsan/.core.o=
.cmd
  if objdump -h kernel/kcsan/core.o | grep -q __ksymtab; then gcc -E -D__GE=
NKSYMS__ -Wp,-MD,kernel/kcsan/.core.o.d  -nostdinc -isystem /usr/lib64/gcc/=
x86_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/include/gene=
rated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/incl=
ude/generated/uapi -I../include/uapi -I./include/generated/uapi -include ..=
/include/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KER=
NEL__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-=
aliasing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-dec=
laration -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse =
-mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=
=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-ra=
x-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D=
1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS=
_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 =
-DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-as=
ynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address=
 -Wno-format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data=
-races=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-=
set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-fr=
ame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -Wdec=
laration-after-statement -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-=
merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -We=
rror=3Ddate-time -Werror=3Dincompatible-pointer-types -Werror=3Ddesignated-=
init -fno-conserve-stack -fno-stack-protector  -fprofile-arcs -ftest-covera=
ge -fno-tree-loop-im -Wno-maybe-uninitialized    -fsanitize=3Dshift  -fsani=
tize=3Dinteger-divide-by-zero  -fsanitize=3Dunreachable  -fsanitize=3Dsigne=
d-integer-overflow  -fsanitize=3Dbounds  -fsanitize=3Dobject-size  -fsaniti=
ze=3Dbool  -fsanitize=3Denum  -Wno-maybe-uninitialized   -I ../kernel/kcsan=
 -I ./kernel/kcsan    -DKBUILD_BASENAME=3D'"core"' -DKBUILD_MODNAME=3D'"cor=
e"' ../kernel/kcsan/core.c | scripts/genksyms/genksyms    -r /dev/null > ke=
rnel/kcsan/.tmp_core.ver; ld -m elf_x86_64  -z max-page-size=3D0x200000 -r =
-o kernel/kcsan/.tmp_core.o kernel/kcsan/core.o -T kernel/kcsan/.tmp_core.v=
er; mv -f kernel/kcsan/.tmp_core.o kernel/kcsan/core.o; rm -f kernel/kcsan/=
.tmp_core.ver; fi
make -f ../scripts/Makefile.build obj=3Dcerts single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dmm single-build=3D1 need-builtin=3D=
1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dfs single-build=3D1 need-builtin=3D=
1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dipc single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dsecurity single-build=3D1 need-buil=
tin=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dcrypto single-build=3D1 need-builti=
n=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dblock single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Ddrivers single-build=3D1 need-built=
in=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dsound single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dsamples single-build=3D1 need-built=
in=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Darch/x86/power single-build=3D1 nee=
d-builtin=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dnet single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dlib single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Darch/x86/lib single-build=3D1 need-=
builtin=3D1 need-modorder=3D1
make -f ../scripts/Makefile.build obj=3Dvirt single-build=3D1 need-builtin=
=3D1 need-modorder=3D1
make[1]: Leaving directory '/home/rdunlap/lnx/next/linux-next-20191119/xx64=
'



--=20
~Randy
Reported-by: Randy Dunlap <rdunlap@infradead.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71%40infradead.org.

--------------C7218DDDD46B2547AEB41C50
Content-Type: text/plain; charset=UTF-8;
 name="config-tsan"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="config-tsan"

IwojIEF1dG9tYXRpY2FsbHkgZ2VuZXJhdGVkIGZpbGU7IERPIE5PVCBFRElULgojIExpbnV4
L3g4Nl82NCA1LjQuMC1yYzggS2VybmVsIENvbmZpZ3VyYXRpb24KIwoKIwojIENvbXBpbGVy
OiBnY2MgKFNVU0UgTGludXgpIDcuNC4xIDIwMTkwOTA1IFtnY2MtNy1icmFuY2ggcmV2aXNp
b24gMjc1NDA3XQojCkNPTkZJR19DQ19JU19HQ0M9eQpDT05GSUdfR0NDX1ZFUlNJT049NzA0
MDEKQ09ORklHX0NMQU5HX1ZFUlNJT049MApDT05GSUdfQ0NfQ0FOX0xJTks9eQpDT05GSUdf
Q0NfSEFTX0FTTV9HT1RPPXkKQ09ORklHX0NDX0hBU19BU01fSU5MSU5FPXkKQ09ORklHX0ND
X0hBU19XQVJOX01BWUJFX1VOSU5JVElBTElaRUQ9eQpDT05GSUdfQ09OU1RSVUNUT1JTPXkK
Q09ORklHX0lSUV9XT1JLPXkKQ09ORklHX0JVSUxEVElNRV9FWFRBQkxFX1NPUlQ9eQpDT05G
SUdfVEhSRUFEX0lORk9fSU5fVEFTSz15CgojCiMgR2VuZXJhbCBzZXR1cAojCkNPTkZJR19J
TklUX0VOVl9BUkdfTElNSVQ9MzIKIyBDT05GSUdfQ09NUElMRV9URVNUIGlzIG5vdCBzZXQK
IyBDT05GSUdfVUFQSV9IRUFERVJfVEVTVCBpcyBub3Qgc2V0CkNPTkZJR19MT0NBTFZFUlNJ
T049IiIKQ09ORklHX0xPQ0FMVkVSU0lPTl9BVVRPPXkKQ09ORklHX0JVSUxEX1NBTFQ9IiIK
Q09ORklHX0hBVkVfS0VSTkVMX0daSVA9eQpDT05GSUdfSEFWRV9LRVJORUxfQlpJUDI9eQpD
T05GSUdfSEFWRV9LRVJORUxfTFpNQT15CkNPTkZJR19IQVZFX0tFUk5FTF9YWj15CkNPTkZJ
R19IQVZFX0tFUk5FTF9MWk89eQpDT05GSUdfSEFWRV9LRVJORUxfTFo0PXkKIyBDT05GSUdf
S0VSTkVMX0daSVAgaXMgbm90IHNldAojIENPTkZJR19LRVJORUxfQlpJUDIgaXMgbm90IHNl
dAojIENPTkZJR19LRVJORUxfTFpNQSBpcyBub3Qgc2V0CiMgQ09ORklHX0tFUk5FTF9YWiBp
cyBub3Qgc2V0CkNPTkZJR19LRVJORUxfTFpPPXkKIyBDT05GSUdfS0VSTkVMX0xaNCBpcyBu
b3Qgc2V0CkNPTkZJR19ERUZBVUxUX0hPU1ROQU1FPSIobm9uZSkiCiMgQ09ORklHX1NZU1ZJ
UEMgaXMgbm90IHNldAojIENPTkZJR19DUk9TU19NRU1PUllfQVRUQUNIIGlzIG5vdCBzZXQK
Q09ORklHX1VTRUxJQj15CkNPTkZJR19IQVZFX0FSQ0hfQVVESVRTWVNDQUxMPXkKCiMKIyBJ
UlEgc3Vic3lzdGVtCiMKQ09ORklHX0dFTkVSSUNfSVJRX1BST0JFPXkKQ09ORklHX0dFTkVS
SUNfSVJRX1NIT1c9eQpDT05GSUdfR0VORVJJQ19JUlFfRUZGRUNUSVZFX0FGRl9NQVNLPXkK
Q09ORklHX0dFTkVSSUNfUEVORElOR19JUlE9eQpDT05GSUdfR0VORVJJQ19JUlFfTUlHUkFU
SU9OPXkKQ09ORklHX0lSUV9ET01BSU49eQpDT05GSUdfSVJRX1NJTT15CkNPTkZJR19JUlFf
RE9NQUlOX0hJRVJBUkNIWT15CkNPTkZJR19HRU5FUklDX0lSUV9NQVRSSVhfQUxMT0NBVE9S
PXkKQ09ORklHX0dFTkVSSUNfSVJRX1JFU0VSVkFUSU9OX01PREU9eQpDT05GSUdfSVJRX0ZP
UkNFRF9USFJFQURJTkc9eQpDT05GSUdfU1BBUlNFX0lSUT15CkNPTkZJR19HRU5FUklDX0lS
UV9ERUJVR0ZTPXkKIyBlbmQgb2YgSVJRIHN1YnN5c3RlbQoKQ09ORklHX0NMT0NLU09VUkNF
X1dBVENIRE9HPXkKQ09ORklHX0FSQ0hfQ0xPQ0tTT1VSQ0VfREFUQT15CkNPTkZJR19BUkNI
X0NMT0NLU09VUkNFX0lOSVQ9eQpDT05GSUdfQ0xPQ0tTT1VSQ0VfVkFMSURBVEVfTEFTVF9D
WUNMRT15CkNPTkZJR19HRU5FUklDX1RJTUVfVlNZU0NBTEw9eQpDT05GSUdfR0VORVJJQ19D
TE9DS0VWRU5UUz15CkNPTkZJR19HRU5FUklDX0NMT0NLRVZFTlRTX0JST0FEQ0FTVD15CkNP
TkZJR19HRU5FUklDX0NMT0NLRVZFTlRTX01JTl9BREpVU1Q9eQpDT05GSUdfR0VORVJJQ19D
TU9TX1VQREFURT15CgojCiMgVGltZXJzIHN1YnN5c3RlbQojCkNPTkZJR19USUNLX09ORVNI
T1Q9eQpDT05GSUdfSFpfUEVSSU9ESUM9eQojIENPTkZJR19OT19IWl9JRExFIGlzIG5vdCBz
ZXQKIyBDT05GSUdfTk9fSFpfRlVMTCBpcyBub3Qgc2V0CkNPTkZJR19OT19IWj15CkNPTkZJ
R19ISUdIX1JFU19USU1FUlM9eQojIGVuZCBvZiBUaW1lcnMgc3Vic3lzdGVtCgpDT05GSUdf
UFJFRU1QVF9OT05FPXkKIyBDT05GSUdfUFJFRU1QVF9WT0xVTlRBUlkgaXMgbm90IHNldAoj
IENPTkZJR19QUkVFTVBUIGlzIG5vdCBzZXQKCiMKIyBDUFUvVGFzayB0aW1lIGFuZCBzdGF0
cyBhY2NvdW50aW5nCiMKQ09ORklHX1RJQ0tfQ1BVX0FDQ09VTlRJTkc9eQojIENPTkZJR19W
SVJUX0NQVV9BQ0NPVU5USU5HX0dFTiBpcyBub3Qgc2V0CiMgQ09ORklHX0lSUV9USU1FX0FD
Q09VTlRJTkcgaXMgbm90IHNldApDT05GSUdfSEFWRV9TQ0hFRF9BVkdfSVJRPXkKQ09ORklH
X0JTRF9QUk9DRVNTX0FDQ1Q9eQpDT05GSUdfQlNEX1BST0NFU1NfQUNDVF9WMz15CkNPTkZJ
R19QU0k9eQojIENPTkZJR19QU0lfREVGQVVMVF9ESVNBQkxFRCBpcyBub3Qgc2V0CiMgZW5k
IG9mIENQVS9UYXNrIHRpbWUgYW5kIHN0YXRzIGFjY291bnRpbmcKCkNPTkZJR19DUFVfSVNP
TEFUSU9OPXkKCiMKIyBSQ1UgU3Vic3lzdGVtCiMKQ09ORklHX1RSRUVfUkNVPXkKQ09ORklH
X1JDVV9FWFBFUlQ9eQpDT05GSUdfU1JDVT15CkNPTkZJR19UUkVFX1NSQ1U9eQpDT05GSUdf
VEFTS1NfUkNVPXkKQ09ORklHX1JDVV9TVEFMTF9DT01NT049eQpDT05GSUdfUkNVX05FRURf
U0VHQ0JMSVNUPXkKQ09ORklHX1JDVV9GQU5PVVQ9NjQKQ09ORklHX1JDVV9GQU5PVVRfTEVB
Rj0xNgpDT05GSUdfUkNVX05PQ0JfQ1BVPXkKIyBlbmQgb2YgUkNVIFN1YnN5c3RlbQoKQ09O
RklHX0JVSUxEX0JJTjJDPXkKQ09ORklHX0lLQ09ORklHPXkKIyBDT05GSUdfSUtIRUFERVJT
IGlzIG5vdCBzZXQKQ09ORklHX0xPR19CVUZfU0hJRlQ9MTcKQ09ORklHX0xPR19DUFVfTUFY
X0JVRl9TSElGVD0xMgpDT05GSUdfUFJJTlRLX1NBRkVfTE9HX0JVRl9TSElGVD0xMwpDT05G
SUdfSEFWRV9VTlNUQUJMRV9TQ0hFRF9DTE9DSz15CgojCiMgU2NoZWR1bGVyIGZlYXR1cmVz
CiMKIyBlbmQgb2YgU2NoZWR1bGVyIGZlYXR1cmVzCgpDT05GSUdfQVJDSF9TVVBQT1JUU19O
VU1BX0JBTEFOQ0lORz15CkNPTkZJR19BUkNIX1dBTlRfQkFUQ0hFRF9VTk1BUF9UTEJfRkxV
U0g9eQpDT05GSUdfQ0NfSEFTX0lOVDEyOD15CkNPTkZJR19BUkNIX1NVUFBPUlRTX0lOVDEy
OD15CiMgQ09ORklHX0NHUk9VUFMgaXMgbm90IHNldAojIENPTkZJR19OQU1FU1BBQ0VTIGlz
IG5vdCBzZXQKQ09ORklHX0NIRUNLUE9JTlRfUkVTVE9SRT15CiMgQ09ORklHX1NDSEVEX0FV
VE9HUk9VUCBpcyBub3Qgc2V0CiMgQ09ORklHX1NZU0ZTX0RFUFJFQ0FURUQgaXMgbm90IHNl
dAojIENPTkZJR19SRUxBWSBpcyBub3Qgc2V0CkNPTkZJR19CTEtfREVWX0lOSVRSRD15CkNP
TkZJR19JTklUUkFNRlNfU09VUkNFPSIiCkNPTkZJR19SRF9HWklQPXkKIyBDT05GSUdfUkRf
QlpJUDIgaXMgbm90IHNldAojIENPTkZJR19SRF9MWk1BIGlzIG5vdCBzZXQKQ09ORklHX1JE
X1haPXkKQ09ORklHX1JEX0xaTz15CiMgQ09ORklHX1JEX0xaNCBpcyBub3Qgc2V0CkNPTkZJ
R19DQ19PUFRJTUlaRV9GT1JfUEVSRk9STUFOQ0U9eQojIENPTkZJR19DQ19PUFRJTUlaRV9G
T1JfU0laRSBpcyBub3Qgc2V0CkNPTkZJR19IQVZFX1VJRDE2PXkKQ09ORklHX1NZU0NUTF9F
WENFUFRJT05fVFJBQ0U9eQpDT05GSUdfSEFWRV9QQ1NQS1JfUExBVEZPUk09eQpDT05GSUdf
RVhQRVJUPXkKQ09ORklHX1VJRDE2PXkKQ09ORklHX01VTFRJVVNFUj15CiMgQ09ORklHX1NH
RVRNQVNLX1NZU0NBTEwgaXMgbm90IHNldApDT05GSUdfU1lTRlNfU1lTQ0FMTD15CiMgQ09O
RklHX0ZIQU5ETEUgaXMgbm90IHNldApDT05GSUdfUE9TSVhfVElNRVJTPXkKQ09ORklHX1BS
SU5USz15CkNPTkZJR19QUklOVEtfTk1JPXkKQ09ORklHX0JVRz15CkNPTkZJR19QQ1NQS1Jf
UExBVEZPUk09eQpDT05GSUdfQkFTRV9GVUxMPXkKQ09ORklHX0ZVVEVYPXkKQ09ORklHX0ZV
VEVYX1BJPXkKIyBDT05GSUdfRVBPTEwgaXMgbm90IHNldAojIENPTkZJR19TSUdOQUxGRCBp
cyBub3Qgc2V0CkNPTkZJR19USU1FUkZEPXkKQ09ORklHX0VWRU5URkQ9eQpDT05GSUdfU0hN
RU09eQojIENPTkZJR19BSU8gaXMgbm90IHNldApDT05GSUdfSU9fVVJJTkc9eQpDT05GSUdf
QURWSVNFX1NZU0NBTExTPXkKQ09ORklHX01FTUJBUlJJRVI9eQpDT05GSUdfS0FMTFNZTVM9
eQpDT05GSUdfS0FMTFNZTVNfQUxMPXkKQ09ORklHX0tBTExTWU1TX0FCU09MVVRFX1BFUkNQ
VT15CkNPTkZJR19LQUxMU1lNU19CQVNFX1JFTEFUSVZFPXkKIyBDT05GSUdfQlBGX1NZU0NB
TEwgaXMgbm90IHNldApDT05GSUdfVVNFUkZBVUxURkQ9eQpDT05GSUdfQVJDSF9IQVNfTUVN
QkFSUklFUl9TWU5DX0NPUkU9eQojIENPTkZJR19SU0VRIGlzIG5vdCBzZXQKQ09ORklHX0VN
QkVEREVEPXkKQ09ORklHX0hBVkVfUEVSRl9FVkVOVFM9eQpDT05GSUdfUEVSRl9VU0VfVk1B
TExPQz15CiMgQ09ORklHX1BDMTA0IGlzIG5vdCBzZXQKCiMKIyBLZXJuZWwgUGVyZm9ybWFu
Y2UgRXZlbnRzIEFuZCBDb3VudGVycwojCkNPTkZJR19QRVJGX0VWRU5UUz15CkNPTkZJR19E
RUJVR19QRVJGX1VTRV9WTUFMTE9DPXkKIyBlbmQgb2YgS2VybmVsIFBlcmZvcm1hbmNlIEV2
ZW50cyBBbmQgQ291bnRlcnMKCkNPTkZJR19WTV9FVkVOVF9DT1VOVEVSUz15CiMgQ09ORklH
X0NPTVBBVF9CUksgaXMgbm90IHNldApDT05GSUdfU0xBQj15CiMgQ09ORklHX1NMVUIgaXMg
bm90IHNldAojIENPTkZJR19TTE9CIGlzIG5vdCBzZXQKQ09ORklHX1NMQUJfTUVSR0VfREVG
QVVMVD15CkNPTkZJR19TTEFCX0ZSRUVMSVNUX1JBTkRPTT15CiMgQ09ORklHX1NIVUZGTEVf
UEFHRV9BTExPQ0FUT1IgaXMgbm90IHNldApDT05GSUdfUFJPRklMSU5HPXkKQ09ORklHX1RS
QUNFUE9JTlRTPXkKIyBlbmQgb2YgR2VuZXJhbCBzZXR1cAoKQ09ORklHXzY0QklUPXkKQ09O
RklHX1g4Nl82ND15CkNPTkZJR19YODY9eQpDT05GSUdfSU5TVFJVQ1RJT05fREVDT0RFUj15
CkNPTkZJR19PVVRQVVRfRk9STUFUPSJlbGY2NC14ODYtNjQiCkNPTkZJR19BUkNIX0RFRkNP
TkZJRz0iYXJjaC94ODYvY29uZmlncy94ODZfNjRfZGVmY29uZmlnIgpDT05GSUdfTE9DS0RF
UF9TVVBQT1JUPXkKQ09ORklHX1NUQUNLVFJBQ0VfU1VQUE9SVD15CkNPTkZJR19NTVU9eQpD
T05GSUdfQVJDSF9NTUFQX1JORF9CSVRTX01JTj0yOApDT05GSUdfQVJDSF9NTUFQX1JORF9C
SVRTX01BWD0zMgpDT05GSUdfQVJDSF9NTUFQX1JORF9DT01QQVRfQklUU19NSU49OApDT05G
SUdfQVJDSF9NTUFQX1JORF9DT01QQVRfQklUU19NQVg9MTYKQ09ORklHX0dFTkVSSUNfSVNB
X0RNQT15CkNPTkZJR19HRU5FUklDX0JVRz15CkNPTkZJR19HRU5FUklDX0JVR19SRUxBVElW
RV9QT0lOVEVSUz15CkNPTkZJR19BUkNIX01BWV9IQVZFX1BDX0ZEQz15CkNPTkZJR19HRU5F
UklDX0NBTElCUkFURV9ERUxBWT15CkNPTkZJR19BUkNIX0hBU19DUFVfUkVMQVg9eQpDT05G
SUdfQVJDSF9IQVNfQ0FDSEVfTElORV9TSVpFPXkKQ09ORklHX0FSQ0hfSEFTX0ZJTFRFUl9Q
R1BST1Q9eQpDT05GSUdfSEFWRV9TRVRVUF9QRVJfQ1BVX0FSRUE9eQpDT05GSUdfTkVFRF9Q
RVJfQ1BVX0VNQkVEX0ZJUlNUX0NIVU5LPXkKQ09ORklHX05FRURfUEVSX0NQVV9QQUdFX0ZJ
UlNUX0NIVU5LPXkKQ09ORklHX0FSQ0hfSElCRVJOQVRJT05fUE9TU0lCTEU9eQpDT05GSUdf
QVJDSF9TVVNQRU5EX1BPU1NJQkxFPXkKQ09ORklHX0FSQ0hfV0FOVF9HRU5FUkFMX0hVR0VU
TEI9eQpDT05GSUdfWk9ORV9ETUEzMj15CkNPTkZJR19BVURJVF9BUkNIPXkKQ09ORklHX0FS
Q0hfU1VQUE9SVFNfREVCVUdfUEFHRUFMTE9DPXkKQ09ORklHX1g4Nl82NF9TTVA9eQpDT05G
SUdfQVJDSF9TVVBQT1JUU19VUFJPQkVTPXkKQ09ORklHX0ZJWF9FQVJMWUNPTl9NRU09eQpD
T05GSUdfUEdUQUJMRV9MRVZFTFM9NApDT05GSUdfQ0NfSEFTX1NBTkVfU1RBQ0tQUk9URUNU
T1I9eQoKIwojIFByb2Nlc3NvciB0eXBlIGFuZCBmZWF0dXJlcwojCiMgQ09ORklHX1pPTkVf
RE1BIGlzIG5vdCBzZXQKQ09ORklHX1NNUD15CkNPTkZJR19YODZfRkVBVFVSRV9OQU1FUz15
CiMgQ09ORklHX1g4Nl9YMkFQSUMgaXMgbm90IHNldAojIENPTkZJR19YODZfTVBQQVJTRSBp
cyBub3Qgc2V0CiMgQ09ORklHX0dPTERGSVNIIGlzIG5vdCBzZXQKIyBDT05GSUdfUkVUUE9M
SU5FIGlzIG5vdCBzZXQKIyBDT05GSUdfWDg2X0NQVV9SRVNDVFJMIGlzIG5vdCBzZXQKQ09O
RklHX1g4Nl9FWFRFTkRFRF9QTEFURk9STT15CiMgQ09ORklHX1g4Nl9HT0xERklTSCBpcyBu
b3Qgc2V0CkNPTkZJR19TQ0hFRF9PTUlUX0ZSQU1FX1BPSU5URVI9eQpDT05GSUdfSFlQRVJW
SVNPUl9HVUVTVD15CkNPTkZJR19QQVJBVklSVD15CkNPTkZJR19QQVJBVklSVF9YWEw9eQoj
IENPTkZJR19QQVJBVklSVF9ERUJVRyBpcyBub3Qgc2V0CiMgQ09ORklHX1BBUkFWSVJUX1NQ
SU5MT0NLUyBpcyBub3Qgc2V0CkNPTkZJR19YODZfSFZfQ0FMTEJBQ0tfVkVDVE9SPXkKQ09O
RklHX1hFTj15CkNPTkZJR19YRU5fUFY9eQpDT05GSUdfWEVOX1BWX1NNUD15CkNPTkZJR19Y
RU5fNTEyR0I9eQpDT05GSUdfWEVOX1NBVkVfUkVTVE9SRT15CiMgQ09ORklHX1hFTl9ERUJV
R19GUyBpcyBub3Qgc2V0CkNPTkZJR19LVk1fR1VFU1Q9eQpDT05GSUdfQVJDSF9DUFVJRExF
X0hBTFRQT0xMPXkKIyBDT05GSUdfUFZIIGlzIG5vdCBzZXQKQ09ORklHX0tWTV9ERUJVR19G
Uz15CkNPTkZJR19QQVJBVklSVF9USU1FX0FDQ09VTlRJTkc9eQpDT05GSUdfUEFSQVZJUlRf
Q0xPQ0s9eQpDT05GSUdfQUNSTl9HVUVTVD15CiMgQ09ORklHX01LOCBpcyBub3Qgc2V0CiMg
Q09ORklHX01QU0MgaXMgbm90IHNldAojIENPTkZJR19NQ09SRTIgaXMgbm90IHNldAojIENP
TkZJR19NQVRPTSBpcyBub3Qgc2V0CkNPTkZJR19HRU5FUklDX0NQVT15CkNPTkZJR19YODZf
SU5URVJOT0RFX0NBQ0hFX1NISUZUPTYKQ09ORklHX1g4Nl9MMV9DQUNIRV9TSElGVD02CkNP
TkZJR19YODZfVFNDPXkKQ09ORklHX1g4Nl9DTVBYQ0hHNjQ9eQpDT05GSUdfWDg2X0NNT1Y9
eQpDT05GSUdfWDg2X01JTklNVU1fQ1BVX0ZBTUlMWT02NApDT05GSUdfWDg2X0RFQlVHQ1RM
TVNSPXkKIyBDT05GSUdfUFJPQ0VTU09SX1NFTEVDVCBpcyBub3Qgc2V0CkNPTkZJR19DUFVf
U1VQX0lOVEVMPXkKQ09ORklHX0NQVV9TVVBfQU1EPXkKQ09ORklHX0NQVV9TVVBfSFlHT049
eQpDT05GSUdfQ1BVX1NVUF9DRU5UQVVSPXkKQ09ORklHX0NQVV9TVVBfWkhBT1hJTj15CkNP
TkZJR19IUEVUX1RJTUVSPXkKQ09ORklHX0RNST15CiMgQ09ORklHX01BWFNNUCBpcyBub3Qg
c2V0CkNPTkZJR19OUl9DUFVTX1JBTkdFX0JFR0lOPTIKQ09ORklHX05SX0NQVVNfUkFOR0Vf
RU5EPTgxOTIKQ09ORklHX05SX0NQVVNfREVGQVVMVD02NApDT05GSUdfTlJfQ1BVUz02NApD
T05GSUdfU0NIRURfU01UPXkKQ09ORklHX1NDSEVEX01DPXkKIyBDT05GSUdfU0NIRURfTUNf
UFJJTyBpcyBub3Qgc2V0CkNPTkZJR19YODZfTE9DQUxfQVBJQz15CkNPTkZJR19YODZfSU9f
QVBJQz15CkNPTkZJR19YODZfUkVST1VURV9GT1JfQlJPS0VOX0JPT1RfSVJRUz15CiMgQ09O
RklHX1g4Nl9NQ0UgaXMgbm90IHNldAoKIwojIFBlcmZvcm1hbmNlIG1vbml0b3JpbmcKIwpD
T05GSUdfUEVSRl9FVkVOVFNfQU1EX1BPV0VSPXkKIyBlbmQgb2YgUGVyZm9ybWFuY2UgbW9u
aXRvcmluZwoKIyBDT05GSUdfWDg2X1ZTWVNDQUxMX0VNVUxBVElPTiBpcyBub3Qgc2V0CkNP
TkZJR19YODZfSU9QTF9JT1BFUk09eQojIENPTkZJR19JOEsgaXMgbm90IHNldApDT05GSUdf
TUlDUk9DT0RFPXkKQ09ORklHX01JQ1JPQ09ERV9JTlRFTD15CiMgQ09ORklHX01JQ1JPQ09E
RV9BTUQgaXMgbm90IHNldAojIENPTkZJR19NSUNST0NPREVfT0xEX0lOVEVSRkFDRSBpcyBu
b3Qgc2V0CiMgQ09ORklHX1g4Nl9NU1IgaXMgbm90IHNldAojIENPTkZJR19YODZfQ1BVSUQg
aXMgbm90IHNldAojIENPTkZJR19YODZfNUxFVkVMIGlzIG5vdCBzZXQKQ09ORklHX1g4Nl9E
SVJFQ1RfR0JQQUdFUz15CiMgQ09ORklHX1g4Nl9DUEFfU1RBVElTVElDUyBpcyBub3Qgc2V0
CiMgQ09ORklHX0FNRF9NRU1fRU5DUllQVCBpcyBub3Qgc2V0CiMgQ09ORklHX05VTUEgaXMg
bm90IHNldApDT05GSUdfQVJDSF9TUEFSU0VNRU1fRU5BQkxFPXkKQ09ORklHX0FSQ0hfU1BB
UlNFTUVNX0RFRkFVTFQ9eQpDT05GSUdfQVJDSF9TRUxFQ1RfTUVNT1JZX01PREVMPXkKQ09O
RklHX0FSQ0hfTUVNT1JZX1BST0JFPXkKQ09ORklHX0lMTEVHQUxfUE9JTlRFUl9WQUxVRT0w
eGRlYWQwMDAwMDAwMDAwMDAKIyBDT05GSUdfWDg2X0NIRUNLX0JJT1NfQ09SUlVQVElPTiBp
cyBub3Qgc2V0CkNPTkZJR19YODZfUkVTRVJWRV9MT1c9NjQKIyBDT05GSUdfTVRSUiBpcyBu
b3Qgc2V0CkNPTkZJR19BUkNIX1JBTkRPTT15CiMgQ09ORklHX1g4Nl9TTUFQIGlzIG5vdCBz
ZXQKIyBDT05GSUdfWDg2X1VNSVAgaXMgbm90IHNldAojIENPTkZJR19YODZfSU5URUxfTVBY
IGlzIG5vdCBzZXQKIyBDT05GSUdfWDg2X0lOVEVMX01FTU9SWV9QUk9URUNUSU9OX0tFWVMg
aXMgbm90IHNldApDT05GSUdfWDg2X0lOVEVMX1RTWF9NT0RFX09GRj15CiMgQ09ORklHX1g4
Nl9JTlRFTF9UU1hfTU9ERV9PTiBpcyBub3Qgc2V0CiMgQ09ORklHX1g4Nl9JTlRFTF9UU1hf
TU9ERV9BVVRPIGlzIG5vdCBzZXQKQ09ORklHX1NFQ0NPTVA9eQojIENPTkZJR19IWl8xMDAg
aXMgbm90IHNldAojIENPTkZJR19IWl8yNTAgaXMgbm90IHNldAojIENPTkZJR19IWl8zMDAg
aXMgbm90IHNldApDT05GSUdfSFpfMTAwMD15CkNPTkZJR19IWj0xMDAwCkNPTkZJR19TQ0hF
RF9IUlRJQ0s9eQpDT05GSUdfS0VYRUM9eQpDT05GSUdfS0VYRUNfRklMRT15CkNPTkZJR19B
UkNIX0hBU19LRVhFQ19QVVJHQVRPUlk9eQojIENPTkZJR19LRVhFQ19TSUcgaXMgbm90IHNl
dApDT05GSUdfQ1JBU0hfRFVNUD15CkNPTkZJR19QSFlTSUNBTF9TVEFSVD0weDEwMDAwMDAK
IyBDT05GSUdfUkVMT0NBVEFCTEUgaXMgbm90IHNldApDT05GSUdfUEhZU0lDQUxfQUxJR049
MHgyMDAwMDAKQ09ORklHX0hPVFBMVUdfQ1BVPXkKIyBDT05GSUdfQk9PVFBBUkFNX0hPVFBM
VUdfQ1BVMCBpcyBub3Qgc2V0CkNPTkZJR19ERUJVR19IT1RQTFVHX0NQVTA9eQpDT05GSUdf
Q09NUEFUX1ZEU089eQojIENPTkZJR19MRUdBQ1lfVlNZU0NBTExfRU1VTEFURSBpcyBub3Qg
c2V0CiMgQ09ORklHX0xFR0FDWV9WU1lTQ0FMTF9YT05MWSBpcyBub3Qgc2V0CkNPTkZJR19M
RUdBQ1lfVlNZU0NBTExfTk9ORT15CkNPTkZJR19DTURMSU5FX0JPT0w9eQpDT05GSUdfQ01E
TElORT0iIgojIENPTkZJR19DTURMSU5FX09WRVJSSURFIGlzIG5vdCBzZXQKIyBDT05GSUdf
TU9ESUZZX0xEVF9TWVNDQUxMIGlzIG5vdCBzZXQKQ09ORklHX0hBVkVfTElWRVBBVENIPXkK
IyBlbmQgb2YgUHJvY2Vzc29yIHR5cGUgYW5kIGZlYXR1cmVzCgpDT05GSUdfQVJDSF9IQVNf
QUREX1BBR0VTPXkKQ09ORklHX0FSQ0hfRU5BQkxFX01FTU9SWV9IT1RQTFVHPXkKQ09ORklH
X0FSQ0hfRU5BQkxFX01FTU9SWV9IT1RSRU1PVkU9eQpDT05GSUdfQVJDSF9FTkFCTEVfU1BM
SVRfUE1EX1BUTE9DSz15CgojCiMgUG93ZXIgbWFuYWdlbWVudCBhbmQgQUNQSSBvcHRpb25z
CiMKQ09ORklHX1NVU1BFTkQ9eQpDT05GSUdfU1VTUEVORF9GUkVFWkVSPXkKQ09ORklHX1NV
U1BFTkRfU0tJUF9TWU5DPXkKQ09ORklHX0hJQkVSTkFURV9DQUxMQkFDS1M9eQpDT05GSUdf
UE1fU0xFRVA9eQpDT05GSUdfUE1fU0xFRVBfU01QPXkKIyBDT05GSUdfUE1fQVVUT1NMRUVQ
IGlzIG5vdCBzZXQKQ09ORklHX1BNX1dBS0VMT0NLUz15CkNPTkZJR19QTV9XQUtFTE9DS1Nf
TElNSVQ9MTAwCiMgQ09ORklHX1BNX1dBS0VMT0NLU19HQyBpcyBub3Qgc2V0CkNPTkZJR19Q
TT15CiMgQ09ORklHX1BNX0RFQlVHIGlzIG5vdCBzZXQKIyBDT05GSUdfV1FfUE9XRVJfRUZG
SUNJRU5UX0RFRkFVTFQgaXMgbm90IHNldApDT05GSUdfQVJDSF9TVVBQT1JUU19BQ1BJPXkK
IyBDT05GSUdfQUNQSSBpcyBub3Qgc2V0CkNPTkZJR19TRkk9eQoKIwojIENQVSBGcmVxdWVu
Y3kgc2NhbGluZwojCiMgQ09ORklHX0NQVV9GUkVRIGlzIG5vdCBzZXQKIyBlbmQgb2YgQ1BV
IEZyZXF1ZW5jeSBzY2FsaW5nCgojCiMgQ1BVIElkbGUKIwojIENPTkZJR19DUFVfSURMRSBp
cyBub3Qgc2V0CiMgZW5kIG9mIENQVSBJZGxlCiMgZW5kIG9mIFBvd2VyIG1hbmFnZW1lbnQg
YW5kIEFDUEkgb3B0aW9ucwoKIwojIEJ1cyBvcHRpb25zIChQQ0kgZXRjLikKIwojIENPTkZJ
R19JU0FfQlVTIGlzIG5vdCBzZXQKQ09ORklHX0lTQV9ETUFfQVBJPXkKIyBDT05GSUdfWDg2
X1NZU0ZCIGlzIG5vdCBzZXQKIyBlbmQgb2YgQnVzIG9wdGlvbnMgKFBDSSBldGMuKQoKIwoj
IEJpbmFyeSBFbXVsYXRpb25zCiMKQ09ORklHX0lBMzJfRU1VTEFUSU9OPXkKIyBDT05GSUdf
WDg2X1gzMiBpcyBub3Qgc2V0CkNPTkZJR19DT01QQVRfMzI9eQpDT05GSUdfQ09NUEFUPXkK
Q09ORklHX0NPTVBBVF9GT1JfVTY0X0FMSUdOTUVOVD15CiMgZW5kIG9mIEJpbmFyeSBFbXVs
YXRpb25zCgojCiMgRmlybXdhcmUgRHJpdmVycwojCiMgQ09ORklHX0VERCBpcyBub3Qgc2V0
CiMgQ09ORklHX0ZJUk1XQVJFX01FTU1BUCBpcyBub3Qgc2V0CkNPTkZJR19ETUlJRD15CkNP
TkZJR19ETUlfU1lTRlM9eQpDT05GSUdfRE1JX1NDQU5fTUFDSElORV9OT05fRUZJX0ZBTExC
QUNLPXkKIyBDT05GSUdfRldfQ0ZHX1NZU0ZTIGlzIG5vdCBzZXQKIyBDT05GSUdfR09PR0xF
X0ZJUk1XQVJFIGlzIG5vdCBzZXQKCiMKIyBUZWdyYSBmaXJtd2FyZSBkcml2ZXIKIwojIGVu
ZCBvZiBUZWdyYSBmaXJtd2FyZSBkcml2ZXIKIyBlbmQgb2YgRmlybXdhcmUgRHJpdmVycwoK
Q09ORklHX0hBVkVfS1ZNPXkKQ09ORklHX1ZJUlRVQUxJWkFUSU9OPXkKIyBDT05GSUdfVkhP
U1RfQ1JPU1NfRU5ESUFOX0xFR0FDWSBpcyBub3Qgc2V0CgojCiMgR2VuZXJhbCBhcmNoaXRl
Y3R1cmUtZGVwZW5kZW50IG9wdGlvbnMKIwpDT05GSUdfQ1JBU0hfQ09SRT15CkNPTkZJR19L
RVhFQ19DT1JFPXkKQ09ORklHX0hPVFBMVUdfU01UPXkKIyBDT05GSUdfT1BST0ZJTEUgaXMg
bm90IHNldApDT05GSUdfSEFWRV9PUFJPRklMRT15CkNPTkZJR19PUFJPRklMRV9OTUlfVElN
RVI9eQpDT05GSUdfS1BST0JFUz15CkNPTkZJR19KVU1QX0xBQkVMPXkKQ09ORklHX1NUQVRJ
Q19LRVlTX1NFTEZURVNUPXkKQ09ORklHX09QVFBST0JFUz15CkNPTkZJR19IQVZFX0VGRklD
SUVOVF9VTkFMSUdORURfQUNDRVNTPXkKQ09ORklHX0FSQ0hfVVNFX0JVSUxUSU5fQlNXQVA9
eQpDT05GSUdfS1JFVFBST0JFUz15CkNPTkZJR19IQVZFX0lPUkVNQVBfUFJPVD15CkNPTkZJ
R19IQVZFX0tQUk9CRVM9eQpDT05GSUdfSEFWRV9LUkVUUFJPQkVTPXkKQ09ORklHX0hBVkVf
T1BUUFJPQkVTPXkKQ09ORklHX0hBVkVfS1BST0JFU19PTl9GVFJBQ0U9eQpDT05GSUdfSEFW
RV9GVU5DVElPTl9FUlJPUl9JTkpFQ1RJT049eQpDT05GSUdfSEFWRV9OTUk9eQpDT05GSUdf
SEFWRV9BUkNIX1RSQUNFSE9PSz15CkNPTkZJR19IQVZFX0RNQV9DT05USUdVT1VTPXkKQ09O
RklHX0dFTkVSSUNfU01QX0lETEVfVEhSRUFEPXkKQ09ORklHX0FSQ0hfSEFTX0ZPUlRJRllf
U09VUkNFPXkKQ09ORklHX0FSQ0hfSEFTX1NFVF9NRU1PUlk9eQpDT05GSUdfQVJDSF9IQVNf
U0VUX0RJUkVDVF9NQVA9eQpDT05GSUdfSEFWRV9BUkNIX1RIUkVBRF9TVFJVQ1RfV0hJVEVM
SVNUPXkKQ09ORklHX0FSQ0hfV0FOVFNfRFlOQU1JQ19UQVNLX1NUUlVDVD15CkNPTkZJR19I
QVZFX0FTTV9NT0RWRVJTSU9OUz15CkNPTkZJR19IQVZFX1JFR1NfQU5EX1NUQUNLX0FDQ0VT
U19BUEk9eQpDT05GSUdfSEFWRV9SU0VRPXkKQ09ORklHX0hBVkVfRlVOQ1RJT05fQVJHX0FD
Q0VTU19BUEk9eQpDT05GSUdfSEFWRV9IV19CUkVBS1BPSU5UPXkKQ09ORklHX0hBVkVfTUlY
RURfQlJFQUtQT0lOVFNfUkVHUz15CkNPTkZJR19IQVZFX1VTRVJfUkVUVVJOX05PVElGSUVS
PXkKQ09ORklHX0hBVkVfUEVSRl9FVkVOVFNfTk1JPXkKQ09ORklHX0hBVkVfSEFSRExPQ0tV
UF9ERVRFQ1RPUl9QRVJGPXkKQ09ORklHX0hBVkVfUEVSRl9SRUdTPXkKQ09ORklHX0hBVkVf
UEVSRl9VU0VSX1NUQUNLX0RVTVA9eQpDT05GSUdfSEFWRV9BUkNIX0pVTVBfTEFCRUw9eQpD
T05GSUdfSEFWRV9BUkNIX0pVTVBfTEFCRUxfUkVMQVRJVkU9eQpDT05GSUdfSEFWRV9SQ1Vf
VEFCTEVfRlJFRT15CkNPTkZJR19BUkNIX0hBVkVfTk1JX1NBRkVfQ01QWENIRz15CkNPTkZJ
R19IQVZFX0NNUFhDSEdfTE9DQUw9eQpDT05GSUdfSEFWRV9DTVBYQ0hHX0RPVUJMRT15CkNP
TkZJR19BUkNIX1dBTlRfQ09NUEFUX0lQQ19QQVJTRV9WRVJTSU9OPXkKQ09ORklHX0FSQ0hf
V0FOVF9PTERfQ09NUEFUX0lQQz15CkNPTkZJR19IQVZFX0FSQ0hfU0VDQ09NUF9GSUxURVI9
eQpDT05GSUdfSEFWRV9BUkNIX1NUQUNLTEVBSz15CkNPTkZJR19IQVZFX1NUQUNLUFJPVEVD
VE9SPXkKQ09ORklHX0NDX0hBU19TVEFDS1BST1RFQ1RPUl9OT05FPXkKIyBDT05GSUdfU1RB
Q0tQUk9URUNUT1IgaXMgbm90IHNldApDT05GSUdfSEFWRV9BUkNIX1dJVEhJTl9TVEFDS19G
UkFNRVM9eQpDT05GSUdfSEFWRV9DT05URVhUX1RSQUNLSU5HPXkKQ09ORklHX0hBVkVfVklS
VF9DUFVfQUNDT1VOVElOR19HRU49eQpDT05GSUdfSEFWRV9JUlFfVElNRV9BQ0NPVU5USU5H
PXkKQ09ORklHX0hBVkVfTU9WRV9QTUQ9eQpDT05GSUdfSEFWRV9BUkNIX1RSQU5TUEFSRU5U
X0hVR0VQQUdFPXkKQ09ORklHX0hBVkVfQVJDSF9UUkFOU1BBUkVOVF9IVUdFUEFHRV9QVUQ9
eQpDT05GSUdfSEFWRV9BUkNIX0hVR0VfVk1BUD15CkNPTkZJR19BUkNIX1dBTlRfSFVHRV9Q
TURfU0hBUkU9eQpDT05GSUdfSEFWRV9BUkNIX1NPRlRfRElSVFk9eQpDT05GSUdfSEFWRV9N
T0RfQVJDSF9TUEVDSUZJQz15CkNPTkZJR19NT0RVTEVTX1VTRV9FTEZfUkVMQT15CkNPTkZJ
R19IQVZFX0lSUV9FWElUX09OX0lSUV9TVEFDSz15CkNPTkZJR19BUkNIX0hBU19FTEZfUkFO
RE9NSVpFPXkKQ09ORklHX0hBVkVfQVJDSF9NTUFQX1JORF9CSVRTPXkKQ09ORklHX0hBVkVf
RVhJVF9USFJFQUQ9eQpDT05GSUdfQVJDSF9NTUFQX1JORF9CSVRTPTI4CkNPTkZJR19IQVZF
X0FSQ0hfTU1BUF9STkRfQ09NUEFUX0JJVFM9eQpDT05GSUdfQVJDSF9NTUFQX1JORF9DT01Q
QVRfQklUUz04CkNPTkZJR19IQVZFX0FSQ0hfQ09NUEFUX01NQVBfQkFTRVM9eQpDT05GSUdf
SEFWRV9DT1BZX1RIUkVBRF9UTFM9eQpDT05GSUdfSEFWRV9TVEFDS19WQUxJREFUSU9OPXkK
Q09ORklHX0lTQV9CVVNfQVBJPXkKQ09ORklHX09MRF9TSUdTVVNQRU5EMz15CkNPTkZJR19D
T01QQVRfT0xEX1NJR0FDVElPTj15CkNPTkZJR19DT01QQVRfMzJCSVRfVElNRT15CkNPTkZJ
R19IQVZFX0FSQ0hfVk1BUF9TVEFDSz15CkNPTkZJR19WTUFQX1NUQUNLPXkKQ09ORklHX0FS
Q0hfSEFTX1NUUklDVF9LRVJORUxfUldYPXkKQ09ORklHX1NUUklDVF9LRVJORUxfUldYPXkK
Q09ORklHX0FSQ0hfSEFTX1NUUklDVF9NT0RVTEVfUldYPXkKQ09ORklHX1NUUklDVF9NT0RV
TEVfUldYPXkKQ09ORklHX0FSQ0hfSEFTX1JFRkNPVU5UPXkKQ09ORklHX1JFRkNPVU5UX0ZV
TEw9eQpDT05GSUdfSEFWRV9BUkNIX1BSRUwzMl9SRUxPQ0FUSU9OUz15CkNPTkZJR19MT0NL
X0VWRU5UX0NPVU5UUz15CkNPTkZJR19BUkNIX0hBU19NRU1fRU5DUllQVD15CgojCiMgR0NP
Vi1iYXNlZCBrZXJuZWwgcHJvZmlsaW5nCiMKQ09ORklHX0dDT1ZfS0VSTkVMPXkKQ09ORklH
X0FSQ0hfSEFTX0dDT1ZfUFJPRklMRV9BTEw9eQpDT05GSUdfR0NPVl9QUk9GSUxFX0FMTD15
CkNPTkZJR19HQ09WX0ZPUk1BVF80Xzc9eQojIGVuZCBvZiBHQ09WLWJhc2VkIGtlcm5lbCBw
cm9maWxpbmcKCkNPTkZJR19QTFVHSU5fSE9TVENDPSIiCkNPTkZJR19IQVZFX0dDQ19QTFVH
SU5TPXkKIyBlbmQgb2YgR2VuZXJhbCBhcmNoaXRlY3R1cmUtZGVwZW5kZW50IG9wdGlvbnMK
CkNPTkZJR19SVF9NVVRFWEVTPXkKQ09ORklHX0JBU0VfU01BTEw9MApDT05GSUdfTU9EVUxF
Uz15CkNPTkZJR19NT0RVTEVfRk9SQ0VfTE9BRD15CkNPTkZJR19NT0RVTEVfVU5MT0FEPXkK
Q09ORklHX01PRFVMRV9GT1JDRV9VTkxPQUQ9eQpDT05GSUdfTU9EVkVSU0lPTlM9eQpDT05G
SUdfQVNNX01PRFZFUlNJT05TPXkKIyBDT05GSUdfTU9EVUxFX1NSQ1ZFUlNJT05fQUxMIGlz
IG5vdCBzZXQKIyBDT05GSUdfTU9EVUxFX1NJRyBpcyBub3Qgc2V0CkNPTkZJR19NT0RVTEVf
Q09NUFJFU1M9eQojIENPTkZJR19NT0RVTEVfQ09NUFJFU1NfR1pJUCBpcyBub3Qgc2V0CkNP
TkZJR19NT0RVTEVfQ09NUFJFU1NfWFo9eQojIENPTkZJR19NT0RVTEVfQUxMT1dfTUlTU0lO
R19OQU1FU1BBQ0VfSU1QT1JUUyBpcyBub3Qgc2V0CiMgQ09ORklHX1VOVVNFRF9TWU1CT0xT
IGlzIG5vdCBzZXQKQ09ORklHX1RSSU1fVU5VU0VEX0tTWU1TPXkKQ09ORklHX01PRFVMRVNf
VFJFRV9MT09LVVA9eQojIENPTkZJR19CTE9DSyBpcyBub3Qgc2V0CkNPTkZJR19QQURBVEE9
eQpDT05GSUdfQVNOMT1tCkNPTkZJR19VTklOTElORV9TUElOX1VOTE9DSz15CkNPTkZJR19B
UkNIX1NVUFBPUlRTX0FUT01JQ19STVc9eQpDT05GSUdfTVVURVhfU1BJTl9PTl9PV05FUj15
CkNPTkZJR19SV1NFTV9TUElOX09OX09XTkVSPXkKQ09ORklHX0xPQ0tfU1BJTl9PTl9PV05F
Uj15CkNPTkZJR19BUkNIX1VTRV9RVUVVRURfU1BJTkxPQ0tTPXkKQ09ORklHX1FVRVVFRF9T
UElOTE9DS1M9eQpDT05GSUdfQVJDSF9VU0VfUVVFVUVEX1JXTE9DS1M9eQpDT05GSUdfUVVF
VUVEX1JXTE9DS1M9eQpDT05GSUdfQVJDSF9IQVNfU1lOQ19DT1JFX0JFRk9SRV9VU0VSTU9E
RT15CkNPTkZJR19BUkNIX0hBU19TWVNDQUxMX1dSQVBQRVI9eQpDT05GSUdfRlJFRVpFUj15
CgojCiMgRXhlY3V0YWJsZSBmaWxlIGZvcm1hdHMKIwpDT05GSUdfQklORk1UX0VMRj15CkNP
TkZJR19DT01QQVRfQklORk1UX0VMRj15CkNPTkZJR19FTEZDT1JFPXkKQ09ORklHX0JJTkZN
VF9TQ1JJUFQ9eQpDT05GSUdfQklORk1UX01JU0M9eQojIENPTkZJR19DT1JFRFVNUCBpcyBu
b3Qgc2V0CiMgZW5kIG9mIEV4ZWN1dGFibGUgZmlsZSBmb3JtYXRzCgojCiMgTWVtb3J5IE1h
bmFnZW1lbnQgb3B0aW9ucwojCkNPTkZJR19TRUxFQ1RfTUVNT1JZX01PREVMPXkKQ09ORklH
X1NQQVJTRU1FTV9NQU5VQUw9eQpDT05GSUdfU1BBUlNFTUVNPXkKQ09ORklHX0hBVkVfTUVN
T1JZX1BSRVNFTlQ9eQpDT05GSUdfU1BBUlNFTUVNX0VYVFJFTUU9eQpDT05GSUdfU1BBUlNF
TUVNX1ZNRU1NQVBfRU5BQkxFPXkKIyBDT05GSUdfU1BBUlNFTUVNX1ZNRU1NQVAgaXMgbm90
IHNldApDT05GSUdfSEFWRV9NRU1CTE9DS19OT0RFX01BUD15CkNPTkZJR19IQVZFX0ZBU1Rf
R1VQPXkKQ09ORklHX01FTU9SWV9JU09MQVRJT049eQpDT05GSUdfTUVNT1JZX0hPVFBMVUc9
eQpDT05GSUdfTUVNT1JZX0hPVFBMVUdfU1BBUlNFPXkKQ09ORklHX01FTU9SWV9IT1RQTFVH
X0RFRkFVTFRfT05MSU5FPXkKIyBDT05GSUdfTUVNT1JZX0hPVFJFTU9WRSBpcyBub3Qgc2V0
CkNPTkZJR19TUExJVF9QVExPQ0tfQ1BVUz00CkNPTkZJR19NRU1PUllfQkFMTE9PTj15CiMg
Q09ORklHX0NPTVBBQ1RJT04gaXMgbm90IHNldApDT05GSUdfTUlHUkFUSU9OPXkKQ09ORklH
X0NPTlRJR19BTExPQz15CkNPTkZJR19QSFlTX0FERFJfVF82NEJJVD15CkNPTkZJR19WSVJU
X1RPX0JVUz15CiMgQ09ORklHX0tTTSBpcyBub3Qgc2V0CkNPTkZJR19ERUZBVUxUX01NQVBf
TUlOX0FERFI9NDA5NgojIENPTkZJR19UUkFOU1BBUkVOVF9IVUdFUEFHRSBpcyBub3Qgc2V0
CkNPTkZJR19BUkNIX1dBTlRTX1RIUF9TV0FQPXkKQ09ORklHX0NMRUFOQ0FDSEU9eQpDT05G
SUdfQ01BPXkKIyBDT05GSUdfQ01BX0RFQlVHIGlzIG5vdCBzZXQKQ09ORklHX0NNQV9ERUJV
R0ZTPXkKQ09ORklHX0NNQV9BUkVBUz03CiMgQ09ORklHX1pQT09MIGlzIG5vdCBzZXQKQ09O
RklHX1pCVUQ9eQpDT05GSUdfWlNNQUxMT0M9eQojIENPTkZJR19QR1RBQkxFX01BUFBJTkcg
aXMgbm90IHNldAojIENPTkZJR19aU01BTExPQ19TVEFUIGlzIG5vdCBzZXQKQ09ORklHX0dF
TkVSSUNfRUFSTFlfSU9SRU1BUD15CiMgQ09ORklHX0RFRkVSUkVEX1NUUlVDVF9QQUdFX0lO
SVQgaXMgbm90IHNldAojIENPTkZJR19JRExFX1BBR0VfVFJBQ0tJTkcgaXMgbm90IHNldApD
T05GSUdfQVJDSF9IQVNfUFRFX0RFVk1BUD15CiMgQ09ORklHX1BFUkNQVV9TVEFUUyBpcyBu
b3Qgc2V0CiMgQ09ORklHX0dVUF9CRU5DSE1BUksgaXMgbm90IHNldApDT05GSUdfQVJDSF9I
QVNfUFRFX1NQRUNJQUw9eQojIGVuZCBvZiBNZW1vcnkgTWFuYWdlbWVudCBvcHRpb25zCgoj
IENPTkZJR19ORVQgaXMgbm90IHNldApDT05GSUdfSEFWRV9FQlBGX0pJVD15CgojCiMgRGV2
aWNlIERyaXZlcnMKIwpDT05GSUdfSEFWRV9FSVNBPXkKIyBDT05GSUdfRUlTQSBpcyBub3Qg
c2V0CkNPTkZJR19IQVZFX1BDST15CiMgQ09ORklHX1BDSSBpcyBub3Qgc2V0CkNPTkZJR19Q
Q0NBUkQ9eQojIENPTkZJR19QQ01DSUEgaXMgbm90IHNldAoKIwojIFBDLWNhcmQgYnJpZGdl
cwojCgojCiMgR2VuZXJpYyBEcml2ZXIgT3B0aW9ucwojCiMgQ09ORklHX0RFVklDRV9OT1RJ
RklDQVRJT05TIGlzIG5vdCBzZXQKQ09ORklHX1VFVkVOVF9IRUxQRVI9eQpDT05GSUdfVUVW
RU5UX0hFTFBFUl9QQVRIPSIiCiMgQ09ORklHX0RFVlRNUEZTIGlzIG5vdCBzZXQKQ09ORklH
X1NUQU5EQUxPTkU9eQpDT05GSUdfUFJFVkVOVF9GSVJNV0FSRV9CVUlMRD15CgojCiMgRmly
bXdhcmUgbG9hZGVyCiMKQ09ORklHX0ZXX0xPQURFUj15CkNPTkZJR19GV19MT0FERVJfUEFH
RURfQlVGPXkKQ09ORklHX0VYVFJBX0ZJUk1XQVJFPSIiCkNPTkZJR19GV19MT0FERVJfVVNF
Ul9IRUxQRVI9eQpDT05GSUdfRldfTE9BREVSX1VTRVJfSEVMUEVSX0ZBTExCQUNLPXkKQ09O
RklHX0ZXX0xPQURFUl9DT01QUkVTUz15CiMgQ09ORklHX0ZXX0NBQ0hFIGlzIG5vdCBzZXQK
IyBlbmQgb2YgRmlybXdhcmUgbG9hZGVyCgpDT05GSUdfV0FOVF9ERVZfQ09SRURVTVA9eQoj
IENPTkZJR19BTExPV19ERVZfQ09SRURVTVAgaXMgbm90IHNldApDT05GSUdfREVCVUdfRFJJ
VkVSPXkKQ09ORklHX0RFQlVHX0RFVlJFUz15CiMgQ09ORklHX0RFQlVHX1RFU1RfRFJJVkVS
X1JFTU9WRSBpcyBub3Qgc2V0CkNPTkZJR19URVNUX0FTWU5DX0RSSVZFUl9QUk9CRT1tCkNP
TkZJR19HRU5FUklDX0NQVV9BVVRPUFJPQkU9eQpDT05GSUdfR0VORVJJQ19DUFVfVlVMTkVS
QUJJTElUSUVTPXkKQ09ORklHX1JFR01BUD15CkNPTkZJR19SRUdNQVBfSTJDPXkKQ09ORklH
X1JFR01BUF9TTElNQlVTPW0KQ09ORklHX1JFR01BUF9TUEk9eQpDT05GSUdfUkVHTUFQX01N
SU89eQpDT05GSUdfUkVHTUFQX0lSUT15CkNPTkZJR19ETUFfU0hBUkVEX0JVRkZFUj15CkNP
TkZJR19ETUFfRkVOQ0VfVFJBQ0U9eQojIGVuZCBvZiBHZW5lcmljIERyaXZlciBPcHRpb25z
CgojCiMgQnVzIGRldmljZXMKIwojIGVuZCBvZiBCdXMgZGV2aWNlcwoKIyBDT05GSUdfR05T
UyBpcyBub3Qgc2V0CiMgQ09ORklHX01URCBpcyBub3Qgc2V0CiMgQ09ORklHX09GIGlzIG5v
dCBzZXQKQ09ORklHX0FSQ0hfTUlHSFRfSEFWRV9QQ19QQVJQT1JUPXkKIyBDT05GSUdfUEFS
UE9SVCBpcyBub3Qgc2V0CgojCiMgTlZNRSBTdXBwb3J0CiMKIyBlbmQgb2YgTlZNRSBTdXBw
b3J0CgojCiMgTWlzYyBkZXZpY2VzCiMKQ09ORklHX1dBVENIX1FVRVVFPXkKQ09ORklHX0FE
NTI1WF9EUE9UPXkKIyBDT05GSUdfQUQ1MjVYX0RQT1RfSTJDIGlzIG5vdCBzZXQKQ09ORklH
X0FENTI1WF9EUE9UX1NQST1tCiMgQ09ORklHX0RVTU1ZX0lSUSBpcyBub3Qgc2V0CkNPTkZJ
R19JQ1M5MzJTNDAxPXkKQ09ORklHX0VOQ0xPU1VSRV9TRVJWSUNFUz1tCiMgQ09ORklHX0FQ
RFM5ODAyQUxTIGlzIG5vdCBzZXQKQ09ORklHX0lTTDI5MDAzPW0KIyBDT05GSUdfSVNMMjkw
MjAgaXMgbm90IHNldApDT05GSUdfU0VOU09SU19UU0wyNTUwPW0KIyBDT05GSUdfU0VOU09S
U19CSDE3NzAgaXMgbm90IHNldAojIENPTkZJR19TRU5TT1JTX0FQRFM5OTBYIGlzIG5vdCBz
ZXQKIyBDT05GSUdfSE1DNjM1MiBpcyBub3Qgc2V0CkNPTkZJR19EUzE2ODI9eQpDT05GSUdf
TEFUVElDRV9FQ1AzX0NPTkZJRz15CkNPTkZJR19TUkFNPXkKQ09ORklHX1hJTElOWF9TREZF
Qz1tCkNPTkZJR19DMlBPUlQ9eQpDT05GSUdfQzJQT1JUX0RVUkFNQVJfMjE1MD1tCgojCiMg
RUVQUk9NIHN1cHBvcnQKIwpDT05GSUdfRUVQUk9NX0FUMjQ9bQpDT05GSUdfRUVQUk9NX0FU
MjU9bQpDT05GSUdfRUVQUk9NX0xFR0FDWT1tCkNPTkZJR19FRVBST01fTUFYNjg3NT15CkNP
TkZJR19FRVBST01fOTNDWDY9bQpDT05GSUdfRUVQUk9NXzkzWFg0Nj1tCkNPTkZJR19FRVBS
T01fSURUXzg5SFBFU1g9bQpDT05GSUdfRUVQUk9NX0VFMTAwND15CiMgZW5kIG9mIEVFUFJP
TSBzdXBwb3J0CgojCiMgVGV4YXMgSW5zdHJ1bWVudHMgc2hhcmVkIHRyYW5zcG9ydCBsaW5l
IGRpc2NpcGxpbmUKIwojIGVuZCBvZiBUZXhhcyBJbnN0cnVtZW50cyBzaGFyZWQgdHJhbnNw
b3J0IGxpbmUgZGlzY2lwbGluZQoKQ09ORklHX0FMVEVSQV9TVEFQTD1tCgojCiMgSW50ZWwg
TUlDICYgcmVsYXRlZCBzdXBwb3J0CiMKQ09ORklHX1ZPUF9CVVM9bQpDT05GSUdfVk9QPW0K
Q09ORklHX1ZIT1NUX1JJTkc9bQojIGVuZCBvZiBJbnRlbCBNSUMgJiByZWxhdGVkIHN1cHBv
cnQKCkNPTkZJR19FQ0hPPXkKIyBlbmQgb2YgTWlzYyBkZXZpY2VzCgpDT05GSUdfSEFWRV9J
REU9eQoKIwojIFNDU0kgZGV2aWNlIHN1cHBvcnQKIwpDT05GSUdfU0NTSV9NT0Q9eQojIGVu
ZCBvZiBTQ1NJIGRldmljZSBzdXBwb3J0CgojIENPTkZJR19NQUNJTlRPU0hfRFJJVkVSUyBp
cyBub3Qgc2V0CgojCiMgSW5wdXQgZGV2aWNlIHN1cHBvcnQKIwojIENPTkZJR19JTlBVVCBp
cyBub3Qgc2V0CgojCiMgSGFyZHdhcmUgSS9PIHBvcnRzCiMKQ09ORklHX1NFUklPPW0KQ09O
RklHX0FSQ0hfTUlHSFRfSEFWRV9QQ19TRVJJTz15CiMgQ09ORklHX1NFUklPX0k4MDQyIGlz
IG5vdCBzZXQKQ09ORklHX1NFUklPX0NUODJDNzEwPW0KQ09ORklHX1NFUklPX0xJQlBTMj1t
CkNPTkZJR19TRVJJT19SQVc9bQojIENPTkZJR19TRVJJT19BTFRFUkFfUFMyIGlzIG5vdCBz
ZXQKQ09ORklHX1NFUklPX1BTMk1VTFQ9bQojIENPTkZJR19TRVJJT19BUkNfUFMyIGlzIG5v
dCBzZXQKIyBDT05GSUdfU0VSSU9fR1BJT19QUzIgaXMgbm90IHNldApDT05GSUdfVVNFUklP
PW0KQ09ORklHX0dBTUVQT1JUPXkKIyBDT05GSUdfR0FNRVBPUlRfTlM1NTggaXMgbm90IHNl
dAojIENPTkZJR19HQU1FUE9SVF9MNCBpcyBub3Qgc2V0CiMgZW5kIG9mIEhhcmR3YXJlIEkv
TyBwb3J0cwojIGVuZCBvZiBJbnB1dCBkZXZpY2Ugc3VwcG9ydAoKIwojIENoYXJhY3RlciBk
ZXZpY2VzCiMKIyBDT05GSUdfVFRZIGlzIG5vdCBzZXQKIyBDT05GSUdfREVWTUVNIGlzIG5v
dCBzZXQKIyBDT05GSUdfREVWS01FTSBpcyBub3Qgc2V0CiMgQ09ORklHX1NFUklBTF9ERVZf
QlVTIGlzIG5vdCBzZXQKQ09ORklHX0lQTUlfSEFORExFUj15CkNPTkZJR19JUE1JX0RNSV9E
RUNPREU9eQpDT05GSUdfSVBNSV9QTEFUX0RBVEE9eQojIENPTkZJR19JUE1JX1BBTklDX0VW
RU5UIGlzIG5vdCBzZXQKIyBDT05GSUdfSVBNSV9ERVZJQ0VfSU5URVJGQUNFIGlzIG5vdCBz
ZXQKQ09ORklHX0lQTUlfU0k9eQpDT05GSUdfSVBNSV9TU0lGPXkKIyBDT05GSUdfSVBNSV9X
QVRDSERPRyBpcyBub3Qgc2V0CkNPTkZJR19JUE1JX1BPV0VST0ZGPXkKIyBDT05GSUdfSFdf
UkFORE9NIGlzIG5vdCBzZXQKQ09ORklHX05WUkFNPW0KQ09ORklHX0hBTkdDSEVDS19USU1F
Uj1tCkNPTkZJR19UQ0dfVFBNPW0KIyBDT05GSUdfVENHX1RJUyBpcyBub3Qgc2V0CiMgQ09O
RklHX1RDR19USVNfU1BJIGlzIG5vdCBzZXQKIyBDT05GSUdfVENHX1RJU19JMkNfQVRNRUwg
aXMgbm90IHNldApDT05GSUdfVENHX1RJU19JMkNfSU5GSU5FT049bQojIENPTkZJR19UQ0df
VElTX0kyQ19OVVZPVE9OIGlzIG5vdCBzZXQKIyBDT05GSUdfVENHX05TQyBpcyBub3Qgc2V0
CiMgQ09ORklHX1RDR19BVE1FTCBpcyBub3Qgc2V0CkNPTkZJR19UQ0dfWEVOPW0KQ09ORklH
X1RDR19WVFBNX1BST1hZPW0KQ09ORklHX1RDR19USVNfU1QzM1pQMjQ9bQpDT05GSUdfVENH
X1RJU19TVDMzWlAyNF9JMkM9bQpDT05GSUdfVENHX1RJU19TVDMzWlAyNF9TUEk9bQojIENP
TkZJR19URUxDTE9DSyBpcyBub3Qgc2V0CiMgZW5kIG9mIENoYXJhY3RlciBkZXZpY2VzCgoj
IENPTkZJR19SQU5ET01fVFJVU1RfQ1BVIGlzIG5vdCBzZXQKIyBDT05GSUdfUkFORE9NX1RS
VVNUX0JPT1RMT0FERVIgaXMgbm90IHNldAoKIwojIEkyQyBzdXBwb3J0CiMKQ09ORklHX0ky
Qz15CkNPTkZJR19JMkNfQk9BUkRJTkZPPXkKQ09ORklHX0kyQ19DT01QQVQ9eQpDT05GSUdf
STJDX0NIQVJERVY9eQpDT05GSUdfSTJDX01VWD1tCgojCiMgTXVsdGlwbGV4ZXIgSTJDIENo
aXAgc3VwcG9ydAojCkNPTkZJR19JMkNfTVVYX0dQSU89bQpDT05GSUdfSTJDX01VWF9MVEM0
MzA2PW0KQ09ORklHX0kyQ19NVVhfUENBOTU0MT1tCiMgQ09ORklHX0kyQ19NVVhfUENBOTU0
eCBpcyBub3Qgc2V0CiMgQ09ORklHX0kyQ19NVVhfUkVHIGlzIG5vdCBzZXQKQ09ORklHX0ky
Q19NVVhfTUxYQ1BMRD1tCiMgZW5kIG9mIE11bHRpcGxleGVyIEkyQyBDaGlwIHN1cHBvcnQK
CkNPTkZJR19JMkNfSEVMUEVSX0FVVE89eQpDT05GSUdfSTJDX1NNQlVTPW0KQ09ORklHX0ky
Q19BTEdPQklUPW0KQ09ORklHX0kyQ19BTEdPUENBPXkKCiMKIyBJMkMgSGFyZHdhcmUgQnVz
IHN1cHBvcnQKIwoKIwojIEkyQyBzeXN0ZW0gYnVzIGRyaXZlcnMgKG1vc3RseSBlbWJlZGRl
ZCAvIHN5c3RlbS1vbi1jaGlwKQojCiMgQ09ORklHX0kyQ19DQlVTX0dQSU8gaXMgbm90IHNl
dApDT05GSUdfSTJDX0RFU0lHTldBUkVfQ09SRT15CkNPTkZJR19JMkNfREVTSUdOV0FSRV9Q
TEFURk9STT15CiMgQ09ORklHX0kyQ19ERVNJR05XQVJFX1NMQVZFIGlzIG5vdCBzZXQKIyBD
T05GSUdfSTJDX0dQSU8gaXMgbm90IHNldApDT05GSUdfSTJDX0tFTVBMRD1tCkNPTkZJR19J
MkNfT0NPUkVTPW0KQ09ORklHX0kyQ19QQ0FfUExBVEZPUk09eQojIENPTkZJR19JMkNfU0lN
VEVDIGlzIG5vdCBzZXQKQ09ORklHX0kyQ19YSUxJTlg9eQoKIwojIEV4dGVybmFsIEkyQy9T
TUJ1cyBhZGFwdGVyIGRyaXZlcnMKIwpDT05GSUdfSTJDX1BBUlBPUlRfTElHSFQ9bQoKIwoj
IE90aGVyIEkyQy9TTUJ1cyBidXMgZHJpdmVycwojCiMgQ09ORklHX0kyQ19NTFhDUExEIGlz
IG5vdCBzZXQKQ09ORklHX0kyQ19DUk9TX0VDX1RVTk5FTD1tCiMgZW5kIG9mIEkyQyBIYXJk
d2FyZSBCdXMgc3VwcG9ydAoKQ09ORklHX0kyQ19TVFVCPW0KIyBDT05GSUdfSTJDX1NMQVZF
IGlzIG5vdCBzZXQKQ09ORklHX0kyQ19ERUJVR19DT1JFPXkKQ09ORklHX0kyQ19ERUJVR19B
TEdPPXkKQ09ORklHX0kyQ19ERUJVR19CVVM9eQojIGVuZCBvZiBJMkMgc3VwcG9ydAoKIyBD
T05GSUdfSTNDIGlzIG5vdCBzZXQKQ09ORklHX1NQST15CkNPTkZJR19TUElfREVCVUc9eQpD
T05GSUdfU1BJX01BU1RFUj15CiMgQ09ORklHX1NQSV9NRU0gaXMgbm90IHNldAoKIwojIFNQ
SSBNYXN0ZXIgQ29udHJvbGxlciBEcml2ZXJzCiMKQ09ORklHX1NQSV9BTFRFUkE9eQojIENP
TkZJR19TUElfQVhJX1NQSV9FTkdJTkUgaXMgbm90IHNldApDT05GSUdfU1BJX0JJVEJBTkc9
eQpDT05GSUdfU1BJX0NBREVOQ0U9eQpDT05GSUdfU1BJX0RFU0lHTldBUkU9eQojIENPTkZJ
R19TUElfRFdfTU1JTyBpcyBub3Qgc2V0CkNPTkZJR19TUElfTlhQX0ZMRVhTUEk9eQojIENP
TkZJR19TUElfR1BJTyBpcyBub3Qgc2V0CkNPTkZJR19TUElfT0NfVElOWT15CkNPTkZJR19T
UElfUk9DS0NISVA9eQpDT05GSUdfU1BJX1NDMThJUzYwMj15CkNPTkZJR19TUElfU0lGSVZF
PXkKIyBDT05GSUdfU1BJX01YSUMgaXMgbm90IHNldAojIENPTkZJR19TUElfWENPTU0gaXMg
bm90IHNldAojIENPTkZJR19TUElfWElMSU5YIGlzIG5vdCBzZXQKQ09ORklHX1NQSV9aWU5R
TVBfR1FTUEk9bQoKIwojIFNQSSBQcm90b2NvbCBNYXN0ZXJzCiMKQ09ORklHX1NQSV9TUElE
RVY9bQojIENPTkZJR19TUElfTE9PUEJBQ0tfVEVTVCBpcyBub3Qgc2V0CiMgQ09ORklHX1NQ
SV9UTEU2MlgwIGlzIG5vdCBzZXQKIyBDT05GSUdfU1BJX1NMQVZFIGlzIG5vdCBzZXQKIyBD
T05GSUdfU1BNSSBpcyBub3Qgc2V0CkNPTkZJR19IU0k9bQpDT05GSUdfSFNJX0JPQVJESU5G
Tz15CgojCiMgSFNJIGNvbnRyb2xsZXJzCiMKCiMKIyBIU0kgY2xpZW50cwojCkNPTkZJR19I
U0lfQ0hBUj1tCiMgQ09ORklHX1BQUyBpcyBub3Qgc2V0CgojCiMgUFRQIGNsb2NrIHN1cHBv
cnQKIwoKIwojIEVuYWJsZSBQSFlMSUIgYW5kIE5FVFdPUktfUEhZX1RJTUVTVEFNUElORyB0
byBzZWUgdGhlIGFkZGl0aW9uYWwgY2xvY2tzLgojCiMgZW5kIG9mIFBUUCBjbG9jayBzdXBw
b3J0CgpDT05GSUdfUElOQ1RSTD15CkNPTkZJR19QSU5NVVg9eQpDT05GSUdfUElOQ09ORj15
CkNPTkZJR19HRU5FUklDX1BJTkNPTkY9eQojIENPTkZJR19ERUJVR19QSU5DVFJMIGlzIG5v
dCBzZXQKIyBDT05GSUdfUElOQ1RSTF9BTUQgaXMgbm90IHNldAojIENPTkZJR19QSU5DVFJM
X01DUDIzUzA4IGlzIG5vdCBzZXQKIyBDT05GSUdfUElOQ1RSTF9TWDE1MFggaXMgbm90IHNl
dApDT05GSUdfUElOQ1RSTF9NQURFUkE9bQpDT05GSUdfUElOQ1RSTF9DUzQ3TDE1PXkKQ09O
RklHX1BJTkNUUkxfQ1M0N0wzNT15CkNPTkZJR19QSU5DVFJMX0NTNDdMODU9eQpDT05GSUdf
R1BJT0xJQj15CkNPTkZJR19HUElPTElCX0ZBU1RQQVRIX0xJTUlUPTUxMgpDT05GSUdfR1BJ
T0xJQl9JUlFDSElQPXkKIyBDT05GSUdfREVCVUdfR1BJTyBpcyBub3Qgc2V0CkNPTkZJR19H
UElPX1NZU0ZTPXkKQ09ORklHX0dQSU9fR0VORVJJQz15CgojCiMgTWVtb3J5IG1hcHBlZCBH
UElPIGRyaXZlcnMKIwojIENPTkZJR19HUElPX0RXQVBCIGlzIG5vdCBzZXQKQ09ORklHX0dQ
SU9fR0VORVJJQ19QTEFURk9STT15CiMgQ09ORklHX0dQSU9fTUI4NlM3WCBpcyBub3Qgc2V0
CiMgQ09ORklHX0dQSU9fTUVOWjEyNyBpcyBub3Qgc2V0CkNPTkZJR19HUElPX1NJT1g9bQpD
T05GSUdfR1BJT19YSUxJTlg9eQojIENPTkZJR19HUElPX0FNRF9GQ0ggaXMgbm90IHNldAoj
IGVuZCBvZiBNZW1vcnkgbWFwcGVkIEdQSU8gZHJpdmVycwoKIwojIFBvcnQtbWFwcGVkIEkv
TyBHUElPIGRyaXZlcnMKIwojIENPTkZJR19HUElPX0Y3MTg4WCBpcyBub3Qgc2V0CiMgQ09O
RklHX0dQSU9fSVQ4NyBpcyBub3Qgc2V0CiMgQ09ORklHX0dQSU9fU0NIMzExWCBpcyBub3Qg
c2V0CiMgQ09ORklHX0dQSU9fV0lOQk9ORCBpcyBub3Qgc2V0CkNPTkZJR19HUElPX1dTMTZD
NDg9eQojIGVuZCBvZiBQb3J0LW1hcHBlZCBJL08gR1BJTyBkcml2ZXJzCgojCiMgSTJDIEdQ
SU8gZXhwYW5kZXJzCiMKQ09ORklHX0dQSU9fQURQNTU4OD15CkNPTkZJR19HUElPX0FEUDU1
ODhfSVJRPXkKIyBDT05GSUdfR1BJT19NQVg3MzAwIGlzIG5vdCBzZXQKQ09ORklHX0dQSU9f
TUFYNzMyWD1tCkNPTkZJR19HUElPX1BDQTk1M1g9eQojIENPTkZJR19HUElPX1BDQTk1M1hf
SVJRIGlzIG5vdCBzZXQKIyBDT05GSUdfR1BJT19QQ0Y4NTdYIGlzIG5vdCBzZXQKIyBDT05G
SUdfR1BJT19UUElDMjgxMCBpcyBub3Qgc2V0CiMgZW5kIG9mIEkyQyBHUElPIGV4cGFuZGVy
cwoKIwojIE1GRCBHUElPIGV4cGFuZGVycwojCiMgQ09ORklHX0dQSU9fQURQNTUyMCBpcyBu
b3Qgc2V0CiMgQ09ORklHX0dQSU9fQVJJWk9OQSBpcyBub3Qgc2V0CkNPTkZJR19HUElPX0JE
OTU3MU1XVj15CkNPTkZJR19HUElPX0RBOTA1Mj15CkNPTkZJR19HUElPX0tFTVBMRD15CkNP
TkZJR19HUElPX0xQODczWD1tCkNPTkZJR19HUElPX01BREVSQT1tCkNPTkZJR19HUElPX1BB
TE1BUz15CiMgQ09ORklHX0dQSU9fUkM1VDU4MyBpcyBub3Qgc2V0CiMgQ09ORklHX0dQSU9f
VFBTNjUwODYgaXMgbm90IHNldApDT05GSUdfR1BJT19UUFM2NTg2WD15CkNPTkZJR19HUElP
X1RQUzY1OTEyPW0KIyBDT05GSUdfR1BJT19UUU1YODYgaXMgbm90IHNldApDT05GSUdfR1BJ
T19UV0w2MDQwPXkKQ09ORklHX0dQSU9fVUNCMTQwMD1tCiMgQ09ORklHX0dQSU9fV004MzFY
IGlzIG5vdCBzZXQKQ09ORklHX0dQSU9fV004MzUwPXkKIyBlbmQgb2YgTUZEIEdQSU8gZXhw
YW5kZXJzCgojCiMgU1BJIEdQSU8gZXhwYW5kZXJzCiMKQ09ORklHX0dQSU9fTUFYMzE5MVg9
eQojIENPTkZJR19HUElPX01BWDczMDEgaXMgbm90IHNldApDT05GSUdfR1BJT19NQzMzODgw
PW0KQ09ORklHX0dQSU9fUElTT1NSPW0KQ09ORklHX0dQSU9fWFJBMTQwMz15CiMgZW5kIG9m
IFNQSSBHUElPIGV4cGFuZGVycwoKQ09ORklHX0dQSU9fTU9DS1VQPXkKQ09ORklHX1cxPW0K
CiMKIyAxLXdpcmUgQnVzIE1hc3RlcnMKIwojIENPTkZJR19XMV9NQVNURVJfRFMyNDgyIGlz
IG5vdCBzZXQKQ09ORklHX1cxX01BU1RFUl9EUzFXTT1tCkNPTkZJR19XMV9NQVNURVJfR1BJ
Tz1tCkNPTkZJR19XMV9NQVNURVJfU0dJPW0KIyBlbmQgb2YgMS13aXJlIEJ1cyBNYXN0ZXJz
CgojCiMgMS13aXJlIFNsYXZlcwojCiMgQ09ORklHX1cxX1NMQVZFX1RIRVJNIGlzIG5vdCBz
ZXQKIyBDT05GSUdfVzFfU0xBVkVfU01FTSBpcyBub3Qgc2V0CkNPTkZJR19XMV9TTEFWRV9E
UzI0MDU9bQojIENPTkZJR19XMV9TTEFWRV9EUzI0MDggaXMgbm90IHNldApDT05GSUdfVzFf
U0xBVkVfRFMyNDEzPW0KQ09ORklHX1cxX1NMQVZFX0RTMjQwNj1tCiMgQ09ORklHX1cxX1NM
QVZFX0RTMjQyMyBpcyBub3Qgc2V0CkNPTkZJR19XMV9TTEFWRV9EUzI4MDU9bQpDT05GSUdf
VzFfU0xBVkVfRFMyNDMwPW0KQ09ORklHX1cxX1NMQVZFX0RTMjQzMT1tCkNPTkZJR19XMV9T
TEFWRV9EUzI0MzM9bQojIENPTkZJR19XMV9TTEFWRV9EUzI0MzNfQ1JDIGlzIG5vdCBzZXQK
Q09ORklHX1cxX1NMQVZFX0RTMjQzOD1tCkNPTkZJR19XMV9TTEFWRV9EUzI1MFg9bQojIENP
TkZJR19XMV9TTEFWRV9EUzI3ODAgaXMgbm90IHNldAojIENPTkZJR19XMV9TTEFWRV9EUzI3
ODEgaXMgbm90IHNldApDT05GSUdfVzFfU0xBVkVfRFMyOEUwND1tCiMgQ09ORklHX1cxX1NM
QVZFX0RTMjhFMTcgaXMgbm90IHNldAojIGVuZCBvZiAxLXdpcmUgU2xhdmVzCgojIENPTkZJ
R19QT1dFUl9BVlMgaXMgbm90IHNldApDT05GSUdfUE9XRVJfUkVTRVQ9eQpDT05GSUdfUE9X
RVJfUkVTRVRfTVQ2MzIzPXkKQ09ORklHX1BPV0VSX1JFU0VUX1JFU1RBUlQ9eQojIENPTkZJ
R19QT1dFUl9TVVBQTFkgaXMgbm90IHNldApDT05GSUdfSFdNT049eQpDT05GSUdfSFdNT05f
VklEPXkKQ09ORklHX0hXTU9OX0RFQlVHX0NISVA9eQoKIwojIE5hdGl2ZSBkcml2ZXJzCiMK
Q09ORklHX1NFTlNPUlNfQUJJVFVHVVJVPXkKQ09ORklHX1NFTlNPUlNfQUJJVFVHVVJVMz1t
CkNPTkZJR19TRU5TT1JTX0FENzMxND15CkNPTkZJR19TRU5TT1JTX0FENzQxND15CkNPTkZJ
R19TRU5TT1JTX0FENzQxOD1tCkNPTkZJR19TRU5TT1JTX0FETTEwMjE9bQpDT05GSUdfU0VO
U09SU19BRE0xMDI1PXkKQ09ORklHX1NFTlNPUlNfQURNMTAyNj1tCkNPTkZJR19TRU5TT1JT
X0FETTEwMjk9eQpDT05GSUdfU0VOU09SU19BRE0xMDMxPXkKIyBDT05GSUdfU0VOU09SU19B
RE05MjQwIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfQURUN1gxMD15CkNPTkZJR19TRU5T
T1JTX0FEVDczMTA9eQpDT05GSUdfU0VOU09SU19BRFQ3NDEwPW0KQ09ORklHX1NFTlNPUlNf
QURUNzQxMT1tCiMgQ09ORklHX1NFTlNPUlNfQURUNzQ2MiBpcyBub3Qgc2V0CkNPTkZJR19T
RU5TT1JTX0FEVDc0NzA9eQojIENPTkZJR19TRU5TT1JTX0FEVDc0NzUgaXMgbm90IHNldAoj
IENPTkZJR19TRU5TT1JTX0FTMzcwIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfQVNDNzYy
MT15CkNPTkZJR19TRU5TT1JTX0FTQjEwMD1tCiMgQ09ORklHX1NFTlNPUlNfQVNQRUVEIGlz
IG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfQVRYUDE9bQojIENPTkZJR19TRU5TT1JTX0RTNjIw
IGlzIG5vdCBzZXQKIyBDT05GSUdfU0VOU09SU19EUzE2MjEgaXMgbm90IHNldApDT05GSUdf
U0VOU09SU19ERUxMX1NNTT15CkNPTkZJR19TRU5TT1JTX0RBOTA1Ml9BREM9eQpDT05GSUdf
U0VOU09SU19GNzE4MDVGPW0KQ09ORklHX1NFTlNPUlNfRjcxODgyRkc9eQpDT05GSUdfU0VO
U09SU19GNzUzNzVTPW0KQ09ORklHX1NFTlNPUlNfTUMxMzc4M19BREM9bQpDT05GSUdfU0VO
U09SU19GU0NITUQ9eQpDT05GSUdfU0VOU09SU19GVFNURVVUQVRFUz15CiMgQ09ORklHX1NF
TlNPUlNfR0w1MThTTSBpcyBub3Qgc2V0CiMgQ09ORklHX1NFTlNPUlNfR0w1MjBTTSBpcyBu
b3Qgc2V0CkNPTkZJR19TRU5TT1JTX0c3NjBBPW0KQ09ORklHX1NFTlNPUlNfRzc2Mj15CkNP
TkZJR19TRU5TT1JTX0hJSDYxMzA9eQojIENPTkZJR19TRU5TT1JTX0lCTUFFTSBpcyBub3Qg
c2V0CkNPTkZJR19TRU5TT1JTX0lCTVBFWD1tCkNPTkZJR19TRU5TT1JTX0lJT19IV01PTj15
CkNPTkZJR19TRU5TT1JTX0NPUkVURU1QPXkKQ09ORklHX1NFTlNPUlNfSVQ4Nz1tCkNPTkZJ
R19TRU5TT1JTX0pDNDI9bQpDT05GSUdfU0VOU09SU19QT1dSMTIyMD1tCkNPTkZJR19TRU5T
T1JTX0xJTkVBR0U9bQpDT05GSUdfU0VOU09SU19MVEMyOTQ1PXkKQ09ORklHX1NFTlNPUlNf
TFRDMjk0Nz1tCkNPTkZJR19TRU5TT1JTX0xUQzI5NDdfSTJDPW0KIyBDT05GSUdfU0VOU09S
U19MVEMyOTQ3X1NQSSBpcyBub3Qgc2V0CiMgQ09ORklHX1NFTlNPUlNfTFRDMjk5MCBpcyBu
b3Qgc2V0CkNPTkZJR19TRU5TT1JTX0xUQzQxNTE9bQpDT05GSUdfU0VOU09SU19MVEM0MjE1
PXkKQ09ORklHX1NFTlNPUlNfTFRDNDIyMj1tCiMgQ09ORklHX1NFTlNPUlNfTFRDNDI0NSBp
cyBub3Qgc2V0CiMgQ09ORklHX1NFTlNPUlNfTFRDNDI2MCBpcyBub3Qgc2V0CkNPTkZJR19T
RU5TT1JTX0xUQzQyNjE9bQojIENPTkZJR19TRU5TT1JTX01BWDExMTEgaXMgbm90IHNldApD
T05GSUdfU0VOU09SU19NQVgxNjA2NT15CkNPTkZJR19TRU5TT1JTX01BWDE2MTk9eQpDT05G
SUdfU0VOU09SU19NQVgxNjY4PW0KQ09ORklHX1NFTlNPUlNfTUFYMTk3PW0KQ09ORklHX1NF
TlNPUlNfTUFYMzE3MjI9bQpDT05GSUdfU0VOU09SU19NQVg2NjIxPXkKQ09ORklHX1NFTlNP
UlNfTUFYNjYzOT15CkNPTkZJR19TRU5TT1JTX01BWDY2NDI9eQojIENPTkZJR19TRU5TT1JT
X01BWDY2NTAgaXMgbm90IHNldApDT05GSUdfU0VOU09SU19NQVg2Njk3PW0KIyBDT05GSUdf
U0VOU09SU19NQVgzMTc5MCBpcyBub3Qgc2V0CkNPTkZJR19TRU5TT1JTX01DUDMwMjE9eQpD
T05GSUdfU0VOU09SU19UQzY1ND1tCkNPTkZJR19TRU5TT1JTX01FTkYyMUJNQ19IV01PTj15
CkNPTkZJR19TRU5TT1JTX0FEQ1hYPXkKIyBDT05GSUdfU0VOU09SU19MTTYzIGlzIG5vdCBz
ZXQKQ09ORklHX1NFTlNPUlNfTE03MD1tCkNPTkZJR19TRU5TT1JTX0xNNzM9eQpDT05GSUdf
U0VOU09SU19MTTc1PW0KQ09ORklHX1NFTlNPUlNfTE03Nz1tCkNPTkZJR19TRU5TT1JTX0xN
Nzg9bQpDT05GSUdfU0VOU09SU19MTTgwPW0KQ09ORklHX1NFTlNPUlNfTE04Mz15CiMgQ09O
RklHX1NFTlNPUlNfTE04NSBpcyBub3Qgc2V0CkNPTkZJR19TRU5TT1JTX0xNODc9eQpDT05G
SUdfU0VOU09SU19MTTkwPW0KQ09ORklHX1NFTlNPUlNfTE05Mj1tCkNPTkZJR19TRU5TT1JT
X0xNOTM9eQpDT05GSUdfU0VOU09SU19MTTk1MjM0PXkKIyBDT05GSUdfU0VOU09SU19MTTk1
MjQxIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfTE05NTI0NT15CkNPTkZJR19TRU5TT1JT
X1BDODczNjA9eQpDT05GSUdfU0VOU09SU19QQzg3NDI3PXkKQ09ORklHX1NFTlNPUlNfTlRD
X1RIRVJNSVNUT1I9bQpDT05GSUdfU0VOU09SU19OQ1Q2NjgzPXkKQ09ORklHX1NFTlNPUlNf
TkNUNjc3NT15CkNPTkZJR19TRU5TT1JTX05DVDc4MDI9bQojIENPTkZJR19TRU5TT1JTX05D
VDc5MDQgaXMgbm90IHNldAojIENPTkZJR19TRU5TT1JTX05QQ003WFggaXMgbm90IHNldApD
T05GSUdfU0VOU09SU19QQ0Y4NTkxPXkKIyBDT05GSUdfUE1CVVMgaXMgbm90IHNldAojIENP
TkZJR19TRU5TT1JTX1NIVDE1IGlzIG5vdCBzZXQKIyBDT05GSUdfU0VOU09SU19TSFQyMSBp
cyBub3Qgc2V0CiMgQ09ORklHX1NFTlNPUlNfU0hUM3ggaXMgbm90IHNldAojIENPTkZJR19T
RU5TT1JTX1NIVEMxIGlzIG5vdCBzZXQKIyBDT05GSUdfU0VOU09SU19ETUUxNzM3IGlzIG5v
dCBzZXQKIyBDT05GSUdfU0VOU09SU19FTUMxNDAzIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNP
UlNfRU1DMjEwMz1tCiMgQ09ORklHX1NFTlNPUlNfRU1DNlcyMDEgaXMgbm90IHNldApDT05G
SUdfU0VOU09SU19TTVNDNDdNMT1tCiMgQ09ORklHX1NFTlNPUlNfU01TQzQ3TTE5MiBpcyBu
b3Qgc2V0CkNPTkZJR19TRU5TT1JTX1NNU0M0N0IzOTc9bQpDT05GSUdfU0VOU09SU19TQ0g1
NlhYX0NPTU1PTj15CkNPTkZJR19TRU5TT1JTX1NDSDU2Mjc9eQojIENPTkZJR19TRU5TT1JT
X1NDSDU2MzYgaXMgbm90IHNldAojIENPTkZJR19TRU5TT1JTX1NUVFM3NTEgaXMgbm90IHNl
dApDT05GSUdfU0VOU09SU19TTU02NjU9bQpDT05GSUdfU0VOU09SU19BREMxMjhEODE4PW0K
IyBDT05GSUdfU0VOU09SU19BRFM3ODI4IGlzIG5vdCBzZXQKIyBDT05GSUdfU0VOU09SU19B
RFM3ODcxIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfQU1DNjgyMT15CkNPTkZJR19TRU5T
T1JTX0lOQTIwOT15CkNPTkZJR19TRU5TT1JTX0lOQTJYWD15CkNPTkZJR19TRU5TT1JTX0lO
QTMyMjE9bQpDT05GSUdfU0VOU09SU19UQzc0PXkKIyBDT05GSUdfU0VOU09SU19USE1DNTAg
aXMgbm90IHNldApDT05GSUdfU0VOU09SU19UTVAxMDI9eQpDT05GSUdfU0VOU09SU19UTVAx
MDM9bQpDT05GSUdfU0VOU09SU19UTVAxMDg9eQpDT05GSUdfU0VOU09SU19UTVA0MDE9bQoj
IENPTkZJR19TRU5TT1JTX1RNUDQyMSBpcyBub3Qgc2V0CiMgQ09ORklHX1NFTlNPUlNfVklB
X0NQVVRFTVAgaXMgbm90IHNldApDT05GSUdfU0VOU09SU19WVDEyMTE9bQojIENPTkZJR19T
RU5TT1JTX1c4Mzc3M0cgaXMgbm90IHNldAojIENPTkZJR19TRU5TT1JTX1c4Mzc4MUQgaXMg
bm90IHNldApDT05GSUdfU0VOU09SU19XODM3OTFEPW0KQ09ORklHX1NFTlNPUlNfVzgzNzky
RD1tCkNPTkZJR19TRU5TT1JTX1c4Mzc5Mz1tCkNPTkZJR19TRU5TT1JTX1c4Mzc5NT1tCiMg
Q09ORklHX1NFTlNPUlNfVzgzNzk1X0ZBTkNUUkwgaXMgbm90IHNldApDT05GSUdfU0VOU09S
U19XODNMNzg1VFM9bQpDT05GSUdfU0VOU09SU19XODNMNzg2Tkc9eQojIENPTkZJR19TRU5T
T1JTX1c4MzYyN0hGIGlzIG5vdCBzZXQKQ09ORklHX1NFTlNPUlNfVzgzNjI3RUhGPW0KQ09O
RklHX1NFTlNPUlNfV004MzFYPXkKQ09ORklHX1NFTlNPUlNfV004MzUwPW0KQ09ORklHX1RI
RVJNQUw9eQpDT05GSUdfVEhFUk1BTF9TVEFUSVNUSUNTPXkKQ09ORklHX1RIRVJNQUxfRU1F
UkdFTkNZX1BPV0VST0ZGX0RFTEFZX01TPTAKIyBDT05GSUdfVEhFUk1BTF9IV01PTiBpcyBu
b3Qgc2V0CiMgQ09ORklHX1RIRVJNQUxfV1JJVEFCTEVfVFJJUFMgaXMgbm90IHNldAojIENP
TkZJR19USEVSTUFMX0RFRkFVTFRfR09WX1NURVBfV0lTRSBpcyBub3Qgc2V0CiMgQ09ORklH
X1RIRVJNQUxfREVGQVVMVF9HT1ZfRkFJUl9TSEFSRSBpcyBub3Qgc2V0CkNPTkZJR19USEVS
TUFMX0RFRkFVTFRfR09WX1VTRVJfU1BBQ0U9eQojIENPTkZJR19USEVSTUFMX0RFRkFVTFRf
R09WX1BPV0VSX0FMTE9DQVRPUiBpcyBub3Qgc2V0CkNPTkZJR19USEVSTUFMX0dPVl9GQUlS
X1NIQVJFPXkKIyBDT05GSUdfVEhFUk1BTF9HT1ZfU1RFUF9XSVNFIGlzIG5vdCBzZXQKIyBD
T05GSUdfVEhFUk1BTF9HT1ZfQkFOR19CQU5HIGlzIG5vdCBzZXQKQ09ORklHX1RIRVJNQUxf
R09WX1VTRVJfU1BBQ0U9eQojIENPTkZJR19USEVSTUFMX0VNVUxBVElPTiBpcyBub3Qgc2V0
CgojCiMgSW50ZWwgdGhlcm1hbCBkcml2ZXJzCiMKIyBDT05GSUdfSU5URUxfUE9XRVJDTEFN
UCBpcyBub3Qgc2V0CgojCiMgQUNQSSBJTlQzNDBYIHRoZXJtYWwgZHJpdmVycwojCiMgZW5k
IG9mIEFDUEkgSU5UMzQwWCB0aGVybWFsIGRyaXZlcnMKIyBlbmQgb2YgSW50ZWwgdGhlcm1h
bCBkcml2ZXJzCgpDT05GSUdfR0VORVJJQ19BRENfVEhFUk1BTD1tCkNPTkZJR19XQVRDSERP
Rz15CkNPTkZJR19XQVRDSERPR19DT1JFPXkKQ09ORklHX1dBVENIRE9HX05PV0FZT1VUPXkK
Q09ORklHX1dBVENIRE9HX0hBTkRMRV9CT09UX0VOQUJMRUQ9eQpDT05GSUdfV0FUQ0hET0df
T1BFTl9USU1FT1VUPTAKIyBDT05GSUdfV0FUQ0hET0dfU1lTRlMgaXMgbm90IHNldAoKIwoj
IFdhdGNoZG9nIFByZXRpbWVvdXQgR292ZXJub3JzCiMKQ09ORklHX1dBVENIRE9HX1BSRVRJ
TUVPVVRfR09WPXkKQ09ORklHX1dBVENIRE9HX1BSRVRJTUVPVVRfR09WX1NFTD1tCiMgQ09O
RklHX1dBVENIRE9HX1BSRVRJTUVPVVRfR09WX05PT1AgaXMgbm90IHNldApDT05GSUdfV0FU
Q0hET0dfUFJFVElNRU9VVF9HT1ZfUEFOSUM9bQpDT05GSUdfV0FUQ0hET0dfUFJFVElNRU9V
VF9ERUZBVUxUX0dPVl9QQU5JQz15CgojCiMgV2F0Y2hkb2cgRGV2aWNlIERyaXZlcnMKIwpD
T05GSUdfU09GVF9XQVRDSERPRz1tCkNPTkZJR19TT0ZUX1dBVENIRE9HX1BSRVRJTUVPVVQ9
eQpDT05GSUdfREE5MDUyX1dBVENIRE9HPXkKQ09ORklHX0RBOTA2M19XQVRDSERPRz1tCiMg
Q09ORklHX0RBOTA2Ml9XQVRDSERPRyBpcyBub3Qgc2V0CiMgQ09ORklHX01FTkYyMUJNQ19X
QVRDSERPRyBpcyBub3Qgc2V0CkNPTkZJR19NRU5aMDY5X1dBVENIRE9HPW0KQ09ORklHX1dN
ODMxWF9XQVRDSERPRz15CkNPTkZJR19XTTgzNTBfV0FUQ0hET0c9eQpDT05GSUdfWElMSU5Y
X1dBVENIRE9HPW0KQ09ORklHX1pJSVJBVkVfV0FUQ0hET0c9bQojIENPTkZJR19DQURFTkNF
X1dBVENIRE9HIGlzIG5vdCBzZXQKIyBDT05GSUdfRFdfV0FUQ0hET0cgaXMgbm90IHNldAoj
IENPTkZJR19NQVg2M1hYX1dBVENIRE9HIGlzIG5vdCBzZXQKIyBDT05GSUdfQUNRVUlSRV9X
RFQgaXMgbm90IHNldApDT05GSUdfQURWQU5URUNIX1dEVD15CkNPTkZJR19FQkNfQzM4NF9X
RFQ9eQpDT05GSUdfRjcxODA4RV9XRFQ9eQojIENPTkZJR19TQkNfRklUUEMyX1dBVENIRE9H
IGlzIG5vdCBzZXQKQ09ORklHX0VVUk9URUNIX1dEVD1tCkNPTkZJR19JQjcwMF9XRFQ9bQpD
T05GSUdfSUJNQVNSPXkKIyBDT05GSUdfV0FGRVJfV0RUIGlzIG5vdCBzZXQKIyBDT05GSUdf
SVQ4NzEyRl9XRFQgaXMgbm90IHNldAojIENPTkZJR19JVDg3X1dEVCBpcyBub3Qgc2V0CkNP
TkZJR19LRU1QTERfV0RUPXkKIyBDT05GSUdfU0MxMjAwX1dEVCBpcyBub3Qgc2V0CkNPTkZJ
R19QQzg3NDEzX1dEVD1tCkNPTkZJR182MFhYX1dEVD15CkNPTkZJR19DUFU1X1dEVD1tCkNP
TkZJR19TTVNDX1NDSDMxMVhfV0RUPW0KQ09ORklHX1NNU0MzN0I3ODdfV0RUPW0KIyBDT05G
SUdfVFFNWDg2X1dEVCBpcyBub3Qgc2V0CkNPTkZJR19XODM2MjdIRl9XRFQ9bQpDT05GSUdf
VzgzODc3Rl9XRFQ9bQpDT05GSUdfVzgzOTc3Rl9XRFQ9eQpDT05GSUdfTUFDSFpfV0RUPXkK
Q09ORklHX1NCQ19FUFhfQzNfV0FUQ0hET0c9eQpDT05GSUdfTUVOX0EyMV9XRFQ9eQojIENP
TkZJR19YRU5fV0RUIGlzIG5vdCBzZXQKQ09ORklHX1NTQl9QT1NTSUJMRT15CiMgQ09ORklH
X1NTQiBpcyBub3Qgc2V0CkNPTkZJR19CQ01BX1BPU1NJQkxFPXkKQ09ORklHX0JDTUE9bQoj
IENPTkZJR19CQ01BX0hPU1RfU09DIGlzIG5vdCBzZXQKQ09ORklHX0JDTUFfRFJJVkVSX0dN
QUNfQ01OPXkKIyBDT05GSUdfQkNNQV9EUklWRVJfR1BJTyBpcyBub3Qgc2V0CiMgQ09ORklH
X0JDTUFfREVCVUcgaXMgbm90IHNldAoKIwojIE11bHRpZnVuY3Rpb24gZGV2aWNlIGRyaXZl
cnMKIwpDT05GSUdfTUZEX0NPUkU9eQpDT05GSUdfTUZEX0FTMzcxMT15CkNPTkZJR19QTUlD
X0FEUDU1MjA9eQpDT05GSUdfTUZEX0FBVDI4NzBfQ09SRT15CkNPTkZJR19NRkRfQkNNNTkw
WFg9bQpDT05GSUdfTUZEX0JEOTU3MU1XVj15CkNPTkZJR19NRkRfQVhQMjBYPW0KQ09ORklH
X01GRF9BWFAyMFhfSTJDPW0KQ09ORklHX01GRF9DUk9TX0VDX0RFVj1tCkNPTkZJR19NRkRf
TUFERVJBPW0KIyBDT05GSUdfTUZEX01BREVSQV9JMkMgaXMgbm90IHNldAojIENPTkZJR19N
RkRfTUFERVJBX1NQSSBpcyBub3Qgc2V0CkNPTkZJR19NRkRfQ1M0N0wxNT15CkNPTkZJR19N
RkRfQ1M0N0wzNT15CkNPTkZJR19NRkRfQ1M0N0w4NT15CiMgQ09ORklHX01GRF9DUzQ3TDkw
IGlzIG5vdCBzZXQKIyBDT05GSUdfTUZEX0NTNDdMOTIgaXMgbm90IHNldAojIENPTkZJR19Q
TUlDX0RBOTAzWCBpcyBub3Qgc2V0CkNPTkZJR19QTUlDX0RBOTA1Mj15CkNPTkZJR19NRkRf
REE5MDUyX1NQST15CkNPTkZJR19NRkRfREE5MDUyX0kyQz15CiMgQ09ORklHX01GRF9EQTkw
NTUgaXMgbm90IHNldApDT05GSUdfTUZEX0RBOTA2Mj15CkNPTkZJR19NRkRfREE5MDYzPW0K
IyBDT05GSUdfTUZEX0RBOTE1MCBpcyBub3Qgc2V0CkNPTkZJR19NRkRfTUMxM1hYWD1tCkNP
TkZJR19NRkRfTUMxM1hYWF9TUEk9bQpDT05GSUdfTUZEX01DMTNYWFhfSTJDPW0KQ09ORklH
X0hUQ19QQVNJQzM9bQojIENPTkZJR19IVENfSTJDUExEIGlzIG5vdCBzZXQKQ09ORklHX01G
RF9LRU1QTEQ9eQpDT05GSUdfTUZEXzg4UE04MDA9bQpDT05GSUdfTUZEXzg4UE04MDU9bQoj
IENPTkZJR19NRkRfODhQTTg2MFggaXMgbm90IHNldAojIENPTkZJR19NRkRfTUFYMTQ1Nzcg
aXMgbm90IHNldApDT05GSUdfTUZEX01BWDc3NjkzPW0KIyBDT05GSUdfTUZEX01BWDc3ODQz
IGlzIG5vdCBzZXQKQ09ORklHX01GRF9NQVg4OTA3PXkKIyBDT05GSUdfTUZEX01BWDg5MjUg
aXMgbm90IHNldApDT05GSUdfTUZEX01BWDg5OTc9eQpDT05GSUdfTUZEX01BWDg5OTg9eQpD
T05GSUdfTUZEX01UNjM5Nz15CkNPTkZJR19NRkRfTUVORjIxQk1DPXkKQ09ORklHX0VaWF9Q
Q0FQPXkKIyBDT05GSUdfTUZEX1JFVFUgaXMgbm90IHNldAojIENPTkZJR19NRkRfUENGNTA2
MzMgaXMgbm90IHNldApDT05GSUdfVUNCMTQwMF9DT1JFPW0KIyBDT05GSUdfTUZEX1JUNTAz
MyBpcyBub3Qgc2V0CkNPTkZJR19NRkRfUkM1VDU4Mz15CiMgQ09ORklHX01GRF9TRUNfQ09S
RSBpcyBub3Qgc2V0CkNPTkZJR19NRkRfU0k0NzZYX0NPUkU9bQpDT05GSUdfTUZEX1NNNTAx
PXkKQ09ORklHX01GRF9TTTUwMV9HUElPPXkKQ09ORklHX01GRF9TS1k4MTQ1Mj1tCiMgQ09O
RklHX01GRF9TTVNDIGlzIG5vdCBzZXQKQ09ORklHX0FCWDUwMF9DT1JFPXkKIyBDT05GSUdf
QUIzMTAwX0NPUkUgaXMgbm90IHNldApDT05GSUdfTUZEX1NZU0NPTj15CkNPTkZJR19NRkRf
VElfQU0zMzVYX1RTQ0FEQz15CiMgQ09ORklHX01GRF9MUDM5NDMgaXMgbm90IHNldAojIENP
TkZJR19NRkRfTFA4Nzg4IGlzIG5vdCBzZXQKQ09ORklHX01GRF9USV9MTVU9eQpDT05GSUdf
TUZEX1BBTE1BUz15CkNPTkZJR19UUFM2MTA1WD1tCiMgQ09ORklHX1RQUzY1MDEwIGlzIG5v
dCBzZXQKQ09ORklHX1RQUzY1MDdYPXkKQ09ORklHX01GRF9UUFM2NTA4Nj1tCiMgQ09ORklH
X01GRF9UUFM2NTA5MCBpcyBub3Qgc2V0CkNPTkZJR19NRkRfVElfTFA4NzNYPXkKQ09ORklH
X01GRF9UUFM2NTg2WD15CiMgQ09ORklHX01GRF9UUFM2NTkxMCBpcyBub3Qgc2V0CkNPTkZJ
R19NRkRfVFBTNjU5MTI9eQpDT05GSUdfTUZEX1RQUzY1OTEyX0kyQz15CkNPTkZJR19NRkRf
VFBTNjU5MTJfU1BJPW0KIyBDT05GSUdfTUZEX1RQUzgwMDMxIGlzIG5vdCBzZXQKIyBDT05G
SUdfVFdMNDAzMF9DT1JFIGlzIG5vdCBzZXQKQ09ORklHX1RXTDYwNDBfQ09SRT15CkNPTkZJ
R19NRkRfV0wxMjczX0NPUkU9bQpDT05GSUdfTUZEX0xNMzUzMz1tCkNPTkZJR19NRkRfVFFN
WDg2PXkKQ09ORklHX01GRF9BUklaT05BPXkKQ09ORklHX01GRF9BUklaT05BX0kyQz15CkNP
TkZJR19NRkRfQVJJWk9OQV9TUEk9bQpDT05GSUdfTUZEX0NTNDdMMjQ9eQpDT05GSUdfTUZE
X1dNNTEwMj15CkNPTkZJR19NRkRfV001MTEwPXkKIyBDT05GSUdfTUZEX1dNODk5NyBpcyBu
b3Qgc2V0CiMgQ09ORklHX01GRF9XTTg5OTggaXMgbm90IHNldApDT05GSUdfTUZEX1dNODQw
MD15CkNPTkZJR19NRkRfV004MzFYPXkKIyBDT05GSUdfTUZEX1dNODMxWF9JMkMgaXMgbm90
IHNldApDT05GSUdfTUZEX1dNODMxWF9TUEk9eQpDT05GSUdfTUZEX1dNODM1MD15CkNPTkZJ
R19NRkRfV004MzUwX0kyQz15CiMgQ09ORklHX01GRF9XTTg5OTQgaXMgbm90IHNldAojIGVu
ZCBvZiBNdWx0aWZ1bmN0aW9uIGRldmljZSBkcml2ZXJzCgpDT05GSUdfUkVHVUxBVE9SPXkK
Q09ORklHX1JFR1VMQVRPUl9ERUJVRz15CkNPTkZJR19SRUdVTEFUT1JfRklYRURfVk9MVEFH
RT1tCkNPTkZJR19SRUdVTEFUT1JfVklSVFVBTF9DT05TVU1FUj1tCkNPTkZJR19SRUdVTEFU
T1JfVVNFUlNQQUNFX0NPTlNVTUVSPW0KIyBDT05GSUdfUkVHVUxBVE9SXzg4UEc4NlggaXMg
bm90IHNldAojIENPTkZJR19SRUdVTEFUT1JfODhQTTgwMCBpcyBub3Qgc2V0CkNPTkZJR19S
RUdVTEFUT1JfQUQ1Mzk4PW0KQ09ORklHX1JFR1VMQVRPUl9BTkFUT1A9bQojIENPTkZJR19S
RUdVTEFUT1JfQUFUMjg3MCBpcyBub3Qgc2V0CiMgQ09ORklHX1JFR1VMQVRPUl9BUklaT05B
X0xETzEgaXMgbm90IHNldAojIENPTkZJR19SRUdVTEFUT1JfQVJJWk9OQV9NSUNTVVBQIGlz
IG5vdCBzZXQKQ09ORklHX1JFR1VMQVRPUl9BUzM3MTE9bQpDT05GSUdfUkVHVUxBVE9SX0FY
UDIwWD1tCiMgQ09ORklHX1JFR1VMQVRPUl9CQ001OTBYWCBpcyBub3Qgc2V0CkNPTkZJR19S
RUdVTEFUT1JfQkQ5NTcxTVdWPW0KIyBDT05GSUdfUkVHVUxBVE9SX0RBOTA1MiBpcyBub3Qg
c2V0CkNPTkZJR19SRUdVTEFUT1JfREE5MDYyPW0KIyBDT05GSUdfUkVHVUxBVE9SX0RBOTIx
MCBpcyBub3Qgc2V0CiMgQ09ORklHX1JFR1VMQVRPUl9EQTkyMTEgaXMgbm90IHNldApDT05G
SUdfUkVHVUxBVE9SX0ZBTjUzNTU1PW0KIyBDT05GSUdfUkVHVUxBVE9SX0dQSU8gaXMgbm90
IHNldAojIENPTkZJR19SRUdVTEFUT1JfSVNMOTMwNSBpcyBub3Qgc2V0CiMgQ09ORklHX1JF
R1VMQVRPUl9JU0w2MjcxQSBpcyBub3Qgc2V0CkNPTkZJR19SRUdVTEFUT1JfTE0zNjNYPXkK
Q09ORklHX1JFR1VMQVRPUl9MUDM5NzE9bQpDT05GSUdfUkVHVUxBVE9SX0xQMzk3Mj15CiMg
Q09ORklHX1JFR1VMQVRPUl9MUDg3MlggaXMgbm90IHNldAojIENPTkZJR19SRUdVTEFUT1Jf
TFA4NzU1IGlzIG5vdCBzZXQKQ09ORklHX1JFR1VMQVRPUl9MVEMzNTg5PW0KIyBDT05GSUdf
UkVHVUxBVE9SX0xUQzM2NzYgaXMgbm90IHNldAojIENPTkZJR19SRUdVTEFUT1JfTUFYMTU4
NiBpcyBub3Qgc2V0CkNPTkZJR19SRUdVTEFUT1JfTUFYODY0OT15CiMgQ09ORklHX1JFR1VM
QVRPUl9NQVg4NjYwIGlzIG5vdCBzZXQKQ09ORklHX1JFR1VMQVRPUl9NQVg4OTA3PXkKQ09O
RklHX1JFR1VMQVRPUl9NQVg4OTUyPXkKQ09ORklHX1JFR1VMQVRPUl9NQVg4OTk3PW0KQ09O
RklHX1JFR1VMQVRPUl9NQVg4OTk4PW0KQ09ORklHX1JFR1VMQVRPUl9NQVg3NzY5Mz1tCkNP
TkZJR19SRUdVTEFUT1JfTUMxM1hYWF9DT1JFPW0KQ09ORklHX1JFR1VMQVRPUl9NQzEzNzgz
PW0KQ09ORklHX1JFR1VMQVRPUl9NQzEzODkyPW0KIyBDT05GSUdfUkVHVUxBVE9SX01UNjMx
MSBpcyBub3Qgc2V0CkNPTkZJR19SRUdVTEFUT1JfTVQ2MzIzPW0KQ09ORklHX1JFR1VMQVRP
Ul9NVDYzOTc9eQojIENPTkZJR19SRUdVTEFUT1JfUEFMTUFTIGlzIG5vdCBzZXQKQ09ORklH
X1JFR1VMQVRPUl9QQ0FQPW0KQ09ORklHX1JFR1VMQVRPUl9QRlVaRTEwMD1tCiMgQ09ORklH
X1JFR1VMQVRPUl9QVjg4MDYwIGlzIG5vdCBzZXQKQ09ORklHX1JFR1VMQVRPUl9QVjg4MDgw
PXkKIyBDT05GSUdfUkVHVUxBVE9SX1BWODgwOTAgaXMgbm90IHNldApDT05GSUdfUkVHVUxB
VE9SX1JDNVQ1ODM9bQojIENPTkZJR19SRUdVTEFUT1JfU0tZODE0NTIgaXMgbm90IHNldApD
T05GSUdfUkVHVUxBVE9SX1NMRzUxMDAwPW0KIyBDT05GSUdfUkVHVUxBVE9SX1RQUzUxNjMy
IGlzIG5vdCBzZXQKIyBDT05GSUdfUkVHVUxBVE9SX1RQUzYxMDVYIGlzIG5vdCBzZXQKQ09O
RklHX1JFR1VMQVRPUl9UUFM2MjM2MD15CiMgQ09ORklHX1JFR1VMQVRPUl9UUFM2NTAyMyBp
cyBub3Qgc2V0CiMgQ09ORklHX1JFR1VMQVRPUl9UUFM2NTA3WCBpcyBub3Qgc2V0CiMgQ09O
RklHX1JFR1VMQVRPUl9UUFM2NTA4NiBpcyBub3Qgc2V0CkNPTkZJR19SRUdVTEFUT1JfVFBT
NjUxMzI9eQpDT05GSUdfUkVHVUxBVE9SX1RQUzY1MjRYPXkKQ09ORklHX1JFR1VMQVRPUl9U
UFM2NTg2WD1tCkNPTkZJR19SRUdVTEFUT1JfVFBTNjU5MTI9bQpDT05GSUdfUkVHVUxBVE9S
X1dNODMxWD1tCkNPTkZJR19SRUdVTEFUT1JfV004MzUwPW0KQ09ORklHX1JFR1VMQVRPUl9X
TTg0MDA9eQpDT05GSUdfQ0VDX0NPUkU9eQojIENPTkZJR19NRURJQV9TVVBQT1JUIGlzIG5v
dCBzZXQKCiMKIyBHcmFwaGljcyBzdXBwb3J0CiMKQ09ORklHX0RSTT1tCkNPTkZJR19EUk1f
TUlQSV9EQkk9bQojIENPTkZJR19EUk1fRFBfQVVYX0NIQVJERVYgaXMgbm90IHNldApDT05G
SUdfRFJNX0RFQlVHX1NFTEZURVNUPW0KQ09ORklHX0RSTV9LTVNfSEVMUEVSPW0KQ09ORklH
X0RSTV9ERUJVR19EUF9NU1RfVE9QT0xPR1lfUkVGUz15CiMgQ09ORklHX0RSTV9GQkRFVl9F
TVVMQVRJT04gaXMgbm90IHNldApDT05GSUdfRFJNX0xPQURfRURJRF9GSVJNV0FSRT15CkNP
TkZJR19EUk1fRFBfQ0VDPXkKQ09ORklHX0RSTV9HRU1fQ01BX0hFTFBFUj15CkNPTkZJR19E
Uk1fS01TX0NNQV9IRUxQRVI9eQpDT05GSUdfRFJNX0dFTV9TSE1FTV9IRUxQRVI9eQpDT05G
SUdfRFJNX1NDSEVEPW0KCiMKIyBJMkMgZW5jb2RlciBvciBoZWxwZXIgY2hpcHMKIwpDT05G
SUdfRFJNX0kyQ19DSDcwMDY9bQpDT05GSUdfRFJNX0kyQ19TSUwxNjQ9bQojIENPTkZJR19E
Uk1fSTJDX05YUF9UREE5OThYIGlzIG5vdCBzZXQKIyBDT05GSUdfRFJNX0kyQ19OWFBfVERB
OTk1MCBpcyBub3Qgc2V0CiMgZW5kIG9mIEkyQyBlbmNvZGVyIG9yIGhlbHBlciBjaGlwcwoK
IwojIEFSTSBkZXZpY2VzCiMKIyBlbmQgb2YgQVJNIGRldmljZXMKCiMKIyBBQ1AgKEF1ZGlv
IENvUHJvY2Vzc29yKSBDb25maWd1cmF0aW9uCiMKIyBlbmQgb2YgQUNQIChBdWRpbyBDb1By
b2Nlc3NvcikgQ29uZmlndXJhdGlvbgoKIyBDT05GSUdfRFJNX1ZHRU0gaXMgbm90IHNldApD
T05GSUdfRFJNX1ZLTVM9bQpDT05GSUdfRFJNX1ZJUlRJT19HUFU9bQpDT05GSUdfRFJNX1BB
TkVMPXkKCiMKIyBEaXNwbGF5IFBhbmVscwojCiMgZW5kIG9mIERpc3BsYXkgUGFuZWxzCgpD
T05GSUdfRFJNX0JSSURHRT15CkNPTkZJR19EUk1fUEFORUxfQlJJREdFPXkKCiMKIyBEaXNw
bGF5IEludGVyZmFjZSBCcmlkZ2VzCiMKQ09ORklHX0RSTV9BTkFMT0dJWF9BTlg3OFhYPW0K
IyBlbmQgb2YgRGlzcGxheSBJbnRlcmZhY2UgQnJpZGdlcwoKQ09ORklHX0RSTV9FVE5BVklW
PW0KQ09ORklHX0RSTV9FVE5BVklWX1RIRVJNQUw9eQpDT05GSUdfVElOWURSTV9IWDgzNTdE
PW0KIyBDT05GSUdfVElOWURSTV9JTEk5MjI1IGlzIG5vdCBzZXQKIyBDT05GSUdfVElOWURS
TV9JTEk5MzQxIGlzIG5vdCBzZXQKQ09ORklHX1RJTllEUk1fTUkwMjgzUVQ9bQpDT05GSUdf
VElOWURSTV9SRVBBUEVSPW0KQ09ORklHX1RJTllEUk1fU1Q3NTg2PW0KQ09ORklHX1RJTllE
Uk1fU1Q3NzM1Uj1tCiMgQ09ORklHX0RSTV9YRU4gaXMgbm90IHNldAojIENPTkZJR19EUk1f
TEVHQUNZIGlzIG5vdCBzZXQKQ09ORklHX0RSTV9QQU5FTF9PUklFTlRBVElPTl9RVUlSS1M9
bQpDT05GSUdfRFJNX0xJQl9SQU5ET009eQoKIwojIEZyYW1lIGJ1ZmZlciBEZXZpY2VzCiMK
Q09ORklHX0ZCX0NNRExJTkU9eQojIENPTkZJR19GQiBpcyBub3Qgc2V0CiMgZW5kIG9mIEZy
YW1lIGJ1ZmZlciBEZXZpY2VzCgojCiMgQmFja2xpZ2h0ICYgTENEIGRldmljZSBzdXBwb3J0
CiMKIyBDT05GSUdfTENEX0NMQVNTX0RFVklDRSBpcyBub3Qgc2V0CkNPTkZJR19CQUNLTElH
SFRfQ0xBU1NfREVWSUNFPW0KIyBDT05GSUdfQkFDS0xJR0hUX0dFTkVSSUMgaXMgbm90IHNl
dAojIENPTkZJR19CQUNLTElHSFRfTE0zNTMzIGlzIG5vdCBzZXQKIyBDT05GSUdfQkFDS0xJ
R0hUX0RBOTA1MiBpcyBub3Qgc2V0CkNPTkZJR19CQUNLTElHSFRfUUNPTV9XTEVEPW0KQ09O
RklHX0JBQ0tMSUdIVF9TQUhBUkE9bQpDT05GSUdfQkFDS0xJR0hUX1dNODMxWD1tCkNPTkZJ
R19CQUNLTElHSFRfQURQNTUyMD1tCkNPTkZJR19CQUNLTElHSFRfQURQODg2MD1tCkNPTkZJ
R19CQUNLTElHSFRfQURQODg3MD1tCkNPTkZJR19CQUNLTElHSFRfQUFUMjg3MD1tCkNPTkZJ
R19CQUNLTElHSFRfTE0zNjM5PW0KQ09ORklHX0JBQ0tMSUdIVF9TS1k4MTQ1Mj1tCkNPTkZJ
R19CQUNLTElHSFRfQVMzNzExPW0KQ09ORklHX0JBQ0tMSUdIVF9HUElPPW0KIyBDT05GSUdf
QkFDS0xJR0hUX0xWNTIwN0xQIGlzIG5vdCBzZXQKIyBDT05GSUdfQkFDS0xJR0hUX0JENjEw
NyBpcyBub3Qgc2V0CiMgQ09ORklHX0JBQ0tMSUdIVF9BUkNYQ05OIGlzIG5vdCBzZXQKIyBl
bmQgb2YgQmFja2xpZ2h0ICYgTENEIGRldmljZSBzdXBwb3J0CgpDT05GSUdfSERNST15CiMg
ZW5kIG9mIEdyYXBoaWNzIHN1cHBvcnQKCkNPTkZJR19TT1VORD15CkNPTkZJR19TT1VORF9P
U1NfQ09SRT15CiMgQ09ORklHX1NPVU5EX09TU19DT1JFX1BSRUNMQUlNIGlzIG5vdCBzZXQK
Q09ORklHX1NORD15CkNPTkZJR19TTkRfVElNRVI9eQpDT05GSUdfU05EX1BDTT1tCkNPTkZJ
R19TTkRfRE1BRU5HSU5FX1BDTT1tCkNPTkZJR19TTkRfU0VRX0RFVklDRT15CkNPTkZJR19T
TkRfUkFXTUlEST15CkNPTkZJR19TTkRfSkFDSz15CkNPTkZJR19TTkRfT1NTRU1VTD15CkNP
TkZJR19TTkRfTUlYRVJfT1NTPW0KIyBDT05GSUdfU05EX1BDTV9PU1MgaXMgbm90IHNldAoj
IENPTkZJR19TTkRfUENNX1RJTUVSIGlzIG5vdCBzZXQKIyBDT05GSUdfU05EX0hSVElNRVIg
aXMgbm90IHNldApDT05GSUdfU05EX0RZTkFNSUNfTUlOT1JTPXkKQ09ORklHX1NORF9NQVhf
Q0FSRFM9MzIKIyBDT05GSUdfU05EX1NVUFBPUlRfT0xEX0FQSSBpcyBub3Qgc2V0CiMgQ09O
RklHX1NORF9WRVJCT1NFX1BSSU5USyBpcyBub3Qgc2V0CkNPTkZJR19TTkRfREVCVUc9eQoj
IENPTkZJR19TTkRfREVCVUdfVkVSQk9TRSBpcyBub3Qgc2V0CkNPTkZJR19TTkRfVk1BU1RF
Uj15CkNPTkZJR19TTkRfRE1BX1NHQlVGPXkKQ09ORklHX1NORF9TRVFVRU5DRVI9eQojIENP
TkZJR19TTkRfU0VRX0RVTU1ZIGlzIG5vdCBzZXQKQ09ORklHX1NORF9TRVFVRU5DRVJfT1NT
PXkKQ09ORklHX1NORF9TRVFfTUlESV9FVkVOVD15CkNPTkZJR19TTkRfU0VRX01JREk9eQpD
T05GSUdfU05EX1NFUV9WSVJNSURJPXkKQ09ORklHX1NORF9NUFU0MDFfVUFSVD15CkNPTkZJ
R19TTkRfQUM5N19DT0RFQz1tCkNPTkZJR19TTkRfRFJJVkVSUz15CkNPTkZJR19TTkRfRFVN
TVk9bQojIENPTkZJR19TTkRfQUxPT1AgaXMgbm90IHNldApDT05GSUdfU05EX1ZJUk1JREk9
eQojIENPTkZJR19TTkRfTVRQQVYgaXMgbm90IHNldAojIENPTkZJR19TTkRfU0VSSUFMX1Ux
NjU1MCBpcyBub3Qgc2V0CkNPTkZJR19TTkRfTVBVNDAxPXkKIyBDT05GSUdfU05EX0FDOTdf
UE9XRVJfU0FWRSBpcyBub3Qgc2V0CgojCiMgSEQtQXVkaW8KIwojIGVuZCBvZiBIRC1BdWRp
bwoKQ09ORklHX1NORF9IREFfUFJFQUxMT0NfU0laRT02NApDT05GSUdfU05EX1NQST15CkNP
TkZJR19TTkRfU09DPW0KQ09ORklHX1NORF9TT0NfQUM5N19CVVM9eQpDT05GSUdfU05EX1NP
Q19HRU5FUklDX0RNQUVOR0lORV9QQ009eQpDT05GSUdfU05EX1NPQ19BTURfQUNQPW0KIyBD
T05GSUdfU05EX1NPQ19BTURfQ1pfREE3MjE5TVg5ODM1N19NQUNIIGlzIG5vdCBzZXQKQ09O
RklHX1NORF9TT0NfQU1EX0NaX1JUNTY0NV9NQUNIPW0KIyBDT05GSUdfU05EX0FUTUVMX1NP
QyBpcyBub3Qgc2V0CgojCiMgU29DIEF1ZGlvIGZvciBGcmVlc2NhbGUgQ1BVcwojCgojCiMg
Q29tbW9uIFNvQyBBdWRpbyBvcHRpb25zIGZvciBGcmVlc2NhbGUgQ1BVczoKIwojIENPTkZJ
R19TTkRfU09DX0ZTTF9BU1JDIGlzIG5vdCBzZXQKQ09ORklHX1NORF9TT0NfRlNMX1NBST1t
CkNPTkZJR19TTkRfU09DX0ZTTF9NUVM9bQpDT05GSUdfU05EX1NPQ19GU0xfQVVETUlYPW0K
Q09ORklHX1NORF9TT0NfRlNMX1NTST1tCiMgQ09ORklHX1NORF9TT0NfRlNMX1NQRElGIGlz
IG5vdCBzZXQKQ09ORklHX1NORF9TT0NfRlNMX0VTQUk9bQpDT05GSUdfU05EX1NPQ19GU0xf
TUlDRklMPW0KIyBDT05GSUdfU05EX1NPQ19JTVhfQVVETVVYIGlzIG5vdCBzZXQKIyBlbmQg
b2YgU29DIEF1ZGlvIGZvciBGcmVlc2NhbGUgQ1BVcwoKQ09ORklHX1NORF9JMlNfSEk2MjEw
X0kyUz1tCkNPTkZJR19TTkRfU09DX0lNRz15CkNPTkZJR19TTkRfU09DX0lNR19JMlNfSU49
bQojIENPTkZJR19TTkRfU09DX0lNR19JMlNfT1VUIGlzIG5vdCBzZXQKQ09ORklHX1NORF9T
T0NfSU1HX1BBUkFMTEVMX09VVD1tCiMgQ09ORklHX1NORF9TT0NfSU1HX1NQRElGX0lOIGlz
IG5vdCBzZXQKIyBDT05GSUdfU05EX1NPQ19JTUdfU1BESUZfT1VUIGlzIG5vdCBzZXQKQ09O
RklHX1NORF9TT0NfSU1HX1BJU1RBQ0hJT19JTlRFUk5BTF9EQUM9bQpDT05GSUdfU05EX1NP
Q19JTlRFTF9TU1RfVE9QTEVWRUw9eQpDT05GSUdfU05EX1NPQ19JTlRFTF9NQUNIPXkKQ09O
RklHX1NORF9TT0NfTVRLX0JUQ1ZTRD1tCkNPTkZJR19TTkRfU09DX1NPRl9UT1BMRVZFTD15
CiMgQ09ORklHX1NORF9TT0NfU09GX0RFVkVMT1BFUl9TVVBQT1JUIGlzIG5vdCBzZXQKQ09O
RklHX1NORF9TT0NfU09GX0lOVEVMX1RPUExFVkVMPXkKCiMKIyBTVE1pY3JvZWxlY3Ryb25p
Y3MgU1RNMzIgU09DIGF1ZGlvIHN1cHBvcnQKIwojIGVuZCBvZiBTVE1pY3JvZWxlY3Ryb25p
Y3MgU1RNMzIgU09DIGF1ZGlvIHN1cHBvcnQKCkNPTkZJR19TTkRfU09DX1hJTElOWF9JMlM9
bQpDT05GSUdfU05EX1NPQ19YSUxJTlhfQVVESU9fRk9STUFUVEVSPW0KQ09ORklHX1NORF9T
T0NfWElMSU5YX1NQRElGPW0KQ09ORklHX1NORF9TT0NfWFRGUEdBX0kyUz1tCkNPTkZJR19T
TkRfU09DX0kyQ19BTkRfU1BJPW0KCiMKIyBDT0RFQyBkcml2ZXJzCiMKQ09ORklHX1NORF9T
T0NfQUM5N19DT0RFQz1tCkNPTkZJR19TTkRfU09DX0FEQVVfVVRJTFM9bQpDT05GSUdfU05E
X1NPQ19BREFVMTcwMT1tCkNPTkZJR19TTkRfU09DX0FEQVUxN1gxPW0KQ09ORklHX1NORF9T
T0NfQURBVTE3NjE9bQojIENPTkZJR19TTkRfU09DX0FEQVUxNzYxX0kyQyBpcyBub3Qgc2V0
CkNPTkZJR19TTkRfU09DX0FEQVUxNzYxX1NQST1tCkNPTkZJR19TTkRfU09DX0FEQVU3MDAy
PW0KQ09ORklHX1NORF9TT0NfQURBVTcxMTg9bQpDT05GSUdfU05EX1NPQ19BREFVNzExOF9I
Vz1tCkNPTkZJR19TTkRfU09DX0FEQVU3MTE4X0kyQz1tCkNPTkZJR19TTkRfU09DX0FLNDEw
ND1tCkNPTkZJR19TTkRfU09DX0FLNDExOD1tCiMgQ09ORklHX1NORF9TT0NfQUs0NDU4IGlz
IG5vdCBzZXQKQ09ORklHX1NORF9TT0NfQUs0NTU0PW0KQ09ORklHX1NORF9TT0NfQUs0NjEz
PW0KQ09ORklHX1NORF9TT0NfQUs0NjQyPW0KIyBDT05GSUdfU05EX1NPQ19BSzUzODYgaXMg
bm90IHNldApDT05GSUdfU05EX1NPQ19BSzU1NTg9bQpDT05GSUdfU05EX1NPQ19BTEM1NjIz
PW0KQ09ORklHX1NORF9TT0NfQkQyODYyMz1tCiMgQ09ORklHX1NORF9TT0NfQlRfU0NPIGlz
IG5vdCBzZXQKQ09ORklHX1NORF9TT0NfQ1JPU19FQ19DT0RFQz1tCkNPTkZJR19TTkRfU09D
X0NTMzVMMzI9bQojIENPTkZJR19TTkRfU09DX0NTMzVMMzMgaXMgbm90IHNldAojIENPTkZJ
R19TTkRfU09DX0NTMzVMMzQgaXMgbm90IHNldApDT05GSUdfU05EX1NPQ19DUzM1TDM1PW0K
Q09ORklHX1NORF9TT0NfQ1MzNUwzNj1tCiMgQ09ORklHX1NORF9TT0NfQ1M0Mkw0MiBpcyBu
b3Qgc2V0CkNPTkZJR19TTkRfU09DX0NTNDJMNTE9bQpDT05GSUdfU05EX1NPQ19DUzQyTDUx
X0kyQz1tCkNPTkZJR19TTkRfU09DX0NTNDJMNzM9bQpDT05GSUdfU05EX1NPQ19DUzQyNjU9
bQpDT05GSUdfU05EX1NPQ19DUzQyNzA9bQpDT05GSUdfU05EX1NPQ19DUzQyNzE9bQpDT05G
SUdfU05EX1NPQ19DUzQyNzFfSTJDPW0KQ09ORklHX1NORF9TT0NfQ1M0MjcxX1NQST1tCkNP
TkZJR19TTkRfU09DX0NTNDJYWDg9bQpDT05GSUdfU05EX1NPQ19DUzQyWFg4X0kyQz1tCiMg
Q09ORklHX1NORF9TT0NfQ1M0MzEzMCBpcyBub3Qgc2V0CkNPTkZJR19TTkRfU09DX0NTNDM0
MT1tCkNPTkZJR19TTkRfU09DX0NTNDM0OT1tCkNPTkZJR19TTkRfU09DX0NTNTNMMzA9bQpD
T05GSUdfU05EX1NPQ19DWDIwNzJYPW0KQ09ORklHX1NORF9TT0NfREE3MjEzPW0KQ09ORklH
X1NORF9TT0NfRE1JQz1tCiMgQ09ORklHX1NORF9TT0NfRVM3MTM0IGlzIG5vdCBzZXQKQ09O
RklHX1NORF9TT0NfRVM3MjQxPW0KIyBDT05GSUdfU05EX1NPQ19FUzgzMTYgaXMgbm90IHNl
dApDT05GSUdfU05EX1NPQ19FUzgzMjg9bQpDT05GSUdfU05EX1NPQ19FUzgzMjhfSTJDPW0K
Q09ORklHX1NORF9TT0NfRVM4MzI4X1NQST1tCiMgQ09ORklHX1NORF9TT0NfR1RNNjAxIGlz
IG5vdCBzZXQKQ09ORklHX1NORF9TT0NfSU5OT19SSzMwMzY9bQpDT05GSUdfU05EX1NPQ19N
QVg5ODA4OD1tCiMgQ09ORklHX1NORF9TT0NfTUFYOTgzNTdBIGlzIG5vdCBzZXQKQ09ORklH
X1NORF9TT0NfTUFYOTg1MDQ9bQojIENPTkZJR19TTkRfU09DX01BWDk4NjcgaXMgbm90IHNl
dApDT05GSUdfU05EX1NPQ19NQVg5ODkyNz1tCiMgQ09ORklHX1NORF9TT0NfTUFYOTgzNzMg
aXMgbm90IHNldAojIENPTkZJR19TTkRfU09DX01BWDk4NjAgaXMgbm90IHNldApDT05GSUdf
U05EX1NPQ19NU004OTE2X1dDRF9ESUdJVEFMPW0KQ09ORklHX1NORF9TT0NfUENNMTY4MT1t
CiMgQ09ORklHX1NORF9TT0NfUENNMTc4OV9JMkMgaXMgbm90IHNldApDT05GSUdfU05EX1NP
Q19QQ00xNzlYPW0KQ09ORklHX1NORF9TT0NfUENNMTc5WF9JMkM9bQpDT05GSUdfU05EX1NP
Q19QQ00xNzlYX1NQST1tCkNPTkZJR19TTkRfU09DX1BDTTE4Nlg9bQpDT05GSUdfU05EX1NP
Q19QQ00xODZYX0kyQz1tCiMgQ09ORklHX1NORF9TT0NfUENNMTg2WF9TUEkgaXMgbm90IHNl
dApDT05GSUdfU05EX1NPQ19QQ00zMDYwPW0KQ09ORklHX1NORF9TT0NfUENNMzA2MF9JMkM9
bQpDT05GSUdfU05EX1NPQ19QQ00zMDYwX1NQST1tCkNPTkZJR19TTkRfU09DX1BDTTMxNjhB
PW0KQ09ORklHX1NORF9TT0NfUENNMzE2OEFfSTJDPW0KQ09ORklHX1NORF9TT0NfUENNMzE2
OEFfU1BJPW0KQ09ORklHX1NORF9TT0NfUENNNTEyeD1tCkNPTkZJR19TTkRfU09DX1BDTTUx
MnhfSTJDPW0KQ09ORklHX1NORF9TT0NfUENNNTEyeF9TUEk9bQojIENPTkZJR19TTkRfU09D
X1JLMzMyOCBpcyBub3Qgc2V0CkNPTkZJR19TTkRfU09DX1JMNjIzMT1tCkNPTkZJR19TTkRf
U09DX1JUNTYxNj1tCkNPTkZJR19TTkRfU09DX1JUNTYzMT1tCkNPTkZJR19TTkRfU09DX1JU
NTY0NT1tCiMgQ09ORklHX1NORF9TT0NfU0dUTDUwMDAgaXMgbm90IHNldApDT05GSUdfU05E
X1NPQ19TSUdNQURTUD1tCkNPTkZJR19TTkRfU09DX1NJR01BRFNQX0kyQz1tCkNPTkZJR19T
TkRfU09DX1NJR01BRFNQX1JFR01BUD1tCkNPTkZJR19TTkRfU09DX1NJTVBMRV9BTVBMSUZJ
RVI9bQpDT05GSUdfU05EX1NPQ19TSVJGX0FVRElPX0NPREVDPW0KQ09ORklHX1NORF9TT0Nf
U1BESUY9bQpDT05GSUdfU05EX1NPQ19TU00yMzA1PW0KQ09ORklHX1NORF9TT0NfU1NNMjYw
Mj1tCkNPTkZJR19TTkRfU09DX1NTTTI2MDJfU1BJPW0KQ09ORklHX1NORF9TT0NfU1NNMjYw
Ml9JMkM9bQpDT05GSUdfU05EX1NPQ19TU000NTY3PW0KIyBDT05GSUdfU05EX1NPQ19TVEEz
MlggaXMgbm90IHNldApDT05GSUdfU05EX1NPQ19TVEEzNTA9bQojIENPTkZJR19TTkRfU09D
X1NUSV9TQVMgaXMgbm90IHNldAojIENPTkZJR19TTkRfU09DX1RBUzI1NTIgaXMgbm90IHNl
dAojIENPTkZJR19TTkRfU09DX1RBUzI1NjIgaXMgbm90IHNldAojIENPTkZJR19TTkRfU09D
X1RBUzI3NzAgaXMgbm90IHNldApDT05GSUdfU05EX1NPQ19UQVM1MDg2PW0KQ09ORklHX1NO
RF9TT0NfVEFTNTcxWD1tCkNPTkZJR19TTkRfU09DX1RBUzU3MjA9bQojIENPTkZJR19TTkRf
U09DX1RBUzY0MjQgaXMgbm90IHNldAojIENPTkZJR19TTkRfU09DX1REQTc0MTkgaXMgbm90
IHNldApDT05GSUdfU05EX1NPQ19URkE5ODc5PW0KQ09ORklHX1NORF9TT0NfVExWMzIwQUlD
MjM9bQojIENPTkZJR19TTkRfU09DX1RMVjMyMEFJQzIzX0kyQyBpcyBub3Qgc2V0CkNPTkZJ
R19TTkRfU09DX1RMVjMyMEFJQzIzX1NQST1tCkNPTkZJR19TTkRfU09DX1RMVjMyMEFJQzMx
WFg9bQojIENPTkZJR19TTkRfU09DX1RMVjMyMEFJQzNYIGlzIG5vdCBzZXQKQ09ORklHX1NO
RF9TT0NfVFMzQTIyN0U9bQpDT05GSUdfU05EX1NPQ19UU0NTNDJYWD1tCkNPTkZJR19TTkRf
U09DX1RTQ1M0NTQ9bQpDT05GSUdfU05EX1NPQ19VREExMzM0PW0KQ09ORklHX1NORF9TT0Nf
V0NEOTMzNT1tCkNPTkZJR19TTkRfU09DX1dNODUxMD1tCiMgQ09ORklHX1NORF9TT0NfV004
NTIzIGlzIG5vdCBzZXQKQ09ORklHX1NORF9TT0NfV004NTI0PW0KQ09ORklHX1NORF9TT0Nf
V004NTgwPW0KIyBDT05GSUdfU05EX1NPQ19XTTg3MTEgaXMgbm90IHNldApDT05GSUdfU05E
X1NPQ19XTTg3Mjg9bQpDT05GSUdfU05EX1NPQ19XTTg3MzE9bQpDT05GSUdfU05EX1NPQ19X
TTg3Mzc9bQpDT05GSUdfU05EX1NPQ19XTTg3NDE9bQpDT05GSUdfU05EX1NPQ19XTTg3NTA9
bQpDT05GSUdfU05EX1NPQ19XTTg3NTM9bQojIENPTkZJR19TTkRfU09DX1dNODc3MCBpcyBu
b3Qgc2V0CiMgQ09ORklHX1NORF9TT0NfV004Nzc2IGlzIG5vdCBzZXQKIyBDT05GSUdfU05E
X1NPQ19XTTg3ODIgaXMgbm90IHNldApDT05GSUdfU05EX1NPQ19XTTg4MDQ9bQojIENPTkZJ
R19TTkRfU09DX1dNODgwNF9JMkMgaXMgbm90IHNldApDT05GSUdfU05EX1NPQ19XTTg4MDRf
U1BJPW0KQ09ORklHX1NORF9TT0NfV004OTAzPW0KQ09ORklHX1NORF9TT0NfV004OTA0PW0K
Q09ORklHX1NORF9TT0NfV004OTYwPW0KQ09ORklHX1NORF9TT0NfV004OTc0PW0KQ09ORklH
X1NORF9TT0NfV004OTc4PW0KIyBDT05GSUdfU05EX1NPQ19XTTg5ODUgaXMgbm90IHNldApD
T05GSUdfU05EX1NPQ19aWF9BVUQ5NlAyMj1tCkNPTkZJR19TTkRfU09DX01BWDk3NTk9bQpD
T05GSUdfU05EX1NPQ19NVDYzNTE9bQojIENPTkZJR19TTkRfU09DX01UNjM1OCBpcyBub3Qg
c2V0CiMgQ09ORklHX1NORF9TT0NfTkFVODU0MCBpcyBub3Qgc2V0CkNPTkZJR19TTkRfU09D
X05BVTg4MTA9bQpDT05GSUdfU05EX1NPQ19OQVU4ODIyPW0KIyBDT05GSUdfU05EX1NPQ19O
QVU4ODI0IGlzIG5vdCBzZXQKQ09ORklHX1NORF9TT0NfVFBBNjEzMEEyPW0KIyBlbmQgb2Yg
Q09ERUMgZHJpdmVycwoKQ09ORklHX1NORF9TSU1QTEVfQ0FSRF9VVElMUz1tCkNPTkZJR19T
TkRfU0lNUExFX0NBUkQ9bQpDT05GSUdfU05EX1g4Nj15CiMgQ09ORklHX1NORF9YRU5fRlJP
TlRFTkQgaXMgbm90IHNldApDT05GSUdfQUM5N19CVVM9bQpDT05GSUdfVVNCX09IQ0lfTElU
VExFX0VORElBTj15CiMgQ09ORklHX1VTQl9TVVBQT1JUIGlzIG5vdCBzZXQKIyBDT05GSUdf
TU1DIGlzIG5vdCBzZXQKIyBDT05GSUdfTUVNU1RJQ0sgaXMgbm90IHNldApDT05GSUdfTkVX
X0xFRFM9eQpDT05GSUdfTEVEU19DTEFTUz1tCkNPTkZJR19MRURTX0NMQVNTX0ZMQVNIPW0K
IyBDT05GSUdfTEVEU19CUklHSFRORVNTX0hXX0NIQU5HRUQgaXMgbm90IHNldAoKIwojIExF
RCBkcml2ZXJzCiMKQ09ORklHX0xFRFNfQVBVPW0KQ09ORklHX0xFRFNfQVMzNjQ1QT1tCkNP
TkZJR19MRURTX0xNMzUzMD1tCkNPTkZJR19MRURTX0xNMzUzMj1tCkNPTkZJR19MRURTX0xN
MzUzMz1tCkNPTkZJR19MRURTX0xNMzY0Mj1tCiMgQ09ORklHX0xFRFNfTE0zNjAxWCBpcyBu
b3Qgc2V0CkNPTkZJR19MRURTX01UNjMyMz1tCkNPTkZJR19MRURTX0dQSU89bQpDT05GSUdf
TEVEU19MUDM5NDQ9bQpDT05GSUdfTEVEU19MUDM5NTI9bQpDT05GSUdfTEVEU19MUDU1WFhf
Q09NTU9OPW0KQ09ORklHX0xFRFNfTFA1NTIxPW0KQ09ORklHX0xFRFNfTFA1NTIzPW0KIyBD
T05GSUdfTEVEU19MUDU1NjIgaXMgbm90IHNldApDT05GSUdfTEVEU19MUDg1MDE9bQpDT05G
SUdfTEVEU19QQ0E5NTVYPW0KQ09ORklHX0xFRFNfUENBOTU1WF9HUElPPXkKIyBDT05GSUdf
TEVEU19QQ0E5NjNYIGlzIG5vdCBzZXQKQ09ORklHX0xFRFNfV004MzFYX1NUQVRVUz1tCiMg
Q09ORklHX0xFRFNfV004MzUwIGlzIG5vdCBzZXQKIyBDT05GSUdfTEVEU19EQTkwNTIgaXMg
bm90IHNldApDT05GSUdfTEVEU19EQUMxMjRTMDg1PW0KIyBDT05GSUdfTEVEU19SRUdVTEFU
T1IgaXMgbm90IHNldAojIENPTkZJR19MRURTX0JEMjgwMiBpcyBub3Qgc2V0CkNPTkZJR19M
RURTX0FEUDU1MjA9bQpDT05GSUdfTEVEU19NQzEzNzgzPW0KQ09ORklHX0xFRFNfVENBNjUw
Nz1tCkNPTkZJR19MRURTX1RMQzU5MVhYPW0KIyBDT05GSUdfTEVEU19NQVg4OTk3IGlzIG5v
dCBzZXQKQ09ORklHX0xFRFNfTE0zNTV4PW0KQ09ORklHX0xFRFNfTUVORjIxQk1DPW0KCiMK
IyBMRUQgZHJpdmVyIGZvciBibGluaygxKSBVU0IgUkdCIExFRCBpcyB1bmRlciBTcGVjaWFs
IEhJRCBkcml2ZXJzIChISURfVEhJTkdNKQojCiMgQ09ORklHX0xFRFNfQkxJTktNIGlzIG5v
dCBzZXQKIyBDT05GSUdfTEVEU19NTFhDUExEIGlzIG5vdCBzZXQKQ09ORklHX0xFRFNfTUxY
UkVHPW0KQ09ORklHX0xFRFNfVVNFUj1tCkNPTkZJR19MRURTX1RJX0xNVV9DT01NT049bQpD
T05GSUdfTEVEU19MTTM2Mjc0PW0KCiMKIyBMRUQgVHJpZ2dlcnMKIwpDT05GSUdfTEVEU19U
UklHR0VSUz15CkNPTkZJR19MRURTX1RSSUdHRVJfVElNRVI9eQpDT05GSUdfTEVEU19UUklH
R0VSX09ORVNIT1Q9bQojIENPTkZJR19MRURTX1RSSUdHRVJfSEVBUlRCRUFUIGlzIG5vdCBz
ZXQKQ09ORklHX0xFRFNfVFJJR0dFUl9CQUNLTElHSFQ9eQpDT05GSUdfTEVEU19UUklHR0VS
X0NQVT15CiMgQ09ORklHX0xFRFNfVFJJR0dFUl9BQ1RJVklUWSBpcyBub3Qgc2V0CkNPTkZJ
R19MRURTX1RSSUdHRVJfR1BJTz15CkNPTkZJR19MRURTX1RSSUdHRVJfREVGQVVMVF9PTj15
CgojCiMgaXB0YWJsZXMgdHJpZ2dlciBpcyB1bmRlciBOZXRmaWx0ZXIgY29uZmlnIChMRUQg
dGFyZ2V0KQojCiMgQ09ORklHX0xFRFNfVFJJR0dFUl9UUkFOU0lFTlQgaXMgbm90IHNldApD
T05GSUdfTEVEU19UUklHR0VSX0NBTUVSQT15CkNPTkZJR19MRURTX1RSSUdHRVJfUEFOSUM9
eQpDT05GSUdfTEVEU19UUklHR0VSX1BBVFRFUk49eQojIENPTkZJR19MRURTX1RSSUdHRVJf
QVVESU8gaXMgbm90IHNldAojIENPTkZJR19BQ0NFU1NJQklMSVRZIGlzIG5vdCBzZXQKQ09O
RklHX0VEQUNfQVRPTUlDX1NDUlVCPXkKQ09ORklHX0VEQUNfU1VQUE9SVD15CkNPTkZJR19F
REFDPXkKIyBDT05GSUdfRURBQ19MRUdBQ1lfU1lTRlMgaXMgbm90IHNldApDT05GSUdfRURB
Q19ERUJVRz15CkNPTkZJR19SVENfTElCPXkKQ09ORklHX1JUQ19NQzE0NjgxOF9MSUI9eQoj
IENPTkZJR19SVENfQ0xBU1MgaXMgbm90IHNldApDT05GSUdfRE1BREVWSUNFUz15CiMgQ09O
RklHX0RNQURFVklDRVNfREVCVUcgaXMgbm90IHNldAoKIwojIERNQSBEZXZpY2VzCiMKQ09O
RklHX0RNQV9FTkdJTkU9eQpDT05GSUdfRE1BX1ZJUlRVQUxfQ0hBTk5FTFM9eQojIENPTkZJ
R19BTFRFUkFfTVNHRE1BIGlzIG5vdCBzZXQKQ09ORklHX0lOVEVMX0lETUE2ND1tCkNPTkZJ
R19RQ09NX0hJRE1BX01HTVQ9bQpDT05GSUdfUUNPTV9ISURNQT15CkNPTkZJR19EV19ETUFD
X0NPUkU9bQpDT05GSUdfRFdfRE1BQz1tCkNPTkZJR19TRl9QRE1BPXkKCiMKIyBETUEgQ2xp
ZW50cwojCiMgQ09ORklHX0FTWU5DX1RYX0RNQSBpcyBub3Qgc2V0CiMgQ09ORklHX0RNQVRF
U1QgaXMgbm90IHNldAoKIwojIERNQUJVRiBvcHRpb25zCiMKQ09ORklHX1NZTkNfRklMRT15
CkNPTkZJR19TV19TWU5DPXkKQ09ORklHX1VETUFCVUY9eQpDT05GSUdfRE1BQlVGX1NFTEZU
RVNUUz15CiMgZW5kIG9mIERNQUJVRiBvcHRpb25zCgojIENPTkZJR19BVVhESVNQTEFZIGlz
IG5vdCBzZXQKIyBDT05GSUdfVUlPIGlzIG5vdCBzZXQKIyBDT05GSUdfVklSVF9EUklWRVJT
IGlzIG5vdCBzZXQKQ09ORklHX1ZJUlRJTz15CkNPTkZJR19WSVJUSU9fTUVOVT15CkNPTkZJ
R19WSVJUSU9fQkFMTE9PTj15CkNPTkZJR19WSVJUSU9fTU1JTz1tCkNPTkZJR19WSVJUSU9f
TU1JT19DTURMSU5FX0RFVklDRVM9eQoKIwojIE1pY3Jvc29mdCBIeXBlci1WIGd1ZXN0IHN1
cHBvcnQKIwojIGVuZCBvZiBNaWNyb3NvZnQgSHlwZXItViBndWVzdCBzdXBwb3J0CgojCiMg
WGVuIGRyaXZlciBzdXBwb3J0CiMKQ09ORklHX1hFTl9CQUxMT09OPXkKQ09ORklHX1hFTl9C
QUxMT09OX01FTU9SWV9IT1RQTFVHPXkKQ09ORklHX1hFTl9CQUxMT09OX01FTU9SWV9IT1RQ
TFVHX0xJTUlUPTUxMgpDT05GSUdfWEVOX1NDUlVCX1BBR0VTX0RFRkFVTFQ9eQojIENPTkZJ
R19YRU5fREVWX0VWVENITiBpcyBub3Qgc2V0CkNPTkZJR19YRU5fQkFDS0VORD15CiMgQ09O
RklHX1hFTkZTIGlzIG5vdCBzZXQKIyBDT05GSUdfWEVOX1NZU19IWVBFUlZJU09SIGlzIG5v
dCBzZXQKQ09ORklHX1hFTl9YRU5CVVNfRlJPTlRFTkQ9bQojIENPTkZJR19YRU5fR05UREVW
IGlzIG5vdCBzZXQKIyBDT05GSUdfWEVOX0dSQU5UX0RFVl9BTExPQyBpcyBub3Qgc2V0CiMg
Q09ORklHX1hFTl9HUkFOVF9ETUFfQUxMT0MgaXMgbm90IHNldApDT05GSUdfU1dJT1RMQl9Y
RU49eQpDT05GSUdfWEVOX1BSSVZDTUQ9bQpDT05GSUdfWEVOX0hBVkVfUFZNTVU9eQpDT05G
SUdfWEVOX0hBVkVfVlBNVT15CiMgZW5kIG9mIFhlbiBkcml2ZXIgc3VwcG9ydAoKQ09ORklH
X0dSRVlCVVM9bQojIENPTkZJR19TVEFHSU5HIGlzIG5vdCBzZXQKQ09ORklHX1g4Nl9QTEFU
Rk9STV9ERVZJQ0VTPXkKQ09ORklHX0RDREJBUz1tCkNPTkZJR19ERUxMX1NNQklPUz1tCkNP
TkZJR19ERUxMX1NNQklPU19TTU09eQpDT05GSUdfREVMTF9SQlU9bQpDT05GSUdfU0FNU1VO
R19MQVBUT1A9bQpDT05GSUdfSU5URUxfUFVOSVRfSVBDPW0KQ09ORklHX01MWF9QTEFURk9S
TT1tCkNPTkZJR19NRkRfQ1JPU19FQz1tCkNPTkZJR19DSFJPTUVfUExBVEZPUk1TPXkKQ09O
RklHX0NIUk9NRU9TX0xBUFRPUD1tCiMgQ09ORklHX0NIUk9NRU9TX1BTVE9SRSBpcyBub3Qg
c2V0CkNPTkZJR19DUk9TX0VDPW0KQ09ORklHX0NST1NfRUNfSTJDPW0KQ09ORklHX0NST1Nf
RUNfU1BJPW0KQ09ORklHX0NST1NfRUNfUFJPVE89eQpDT05GSUdfQ1JPU19FQ19DSEFSREVW
PW0KQ09ORklHX0NST1NfRUNfTElHSFRCQVI9bQpDT05GSUdfQ1JPU19FQ19ERUJVR0ZTPW0K
IyBDT05GSUdfQ1JPU19FQ19TWVNGUyBpcyBub3Qgc2V0CiMgQ09ORklHX01FTExBTk9YX1BM
QVRGT1JNIGlzIG5vdCBzZXQKIyBDT05GSUdfSFdTUElOTE9DSyBpcyBub3Qgc2V0CgojCiMg
Q2xvY2sgU291cmNlIGRyaXZlcnMKIwpDT05GSUdfQ0xLRVZUX0k4MjUzPXkKQ09ORklHX0k4
MjUzX0xPQ0s9eQpDT05GSUdfQ0xLQkxEX0k4MjUzPXkKIyBlbmQgb2YgQ2xvY2sgU291cmNl
IGRyaXZlcnMKCiMgQ09ORklHX01BSUxCT1ggaXMgbm90IHNldAojIENPTkZJR19JT01NVV9T
VVBQT1JUIGlzIG5vdCBzZXQKCiMKIyBSZW1vdGVwcm9jIGRyaXZlcnMKIwpDT05GSUdfUkVN
T1RFUFJPQz15CiMgZW5kIG9mIFJlbW90ZXByb2MgZHJpdmVycwoKIwojIFJwbXNnIGRyaXZl
cnMKIwpDT05GSUdfUlBNU0c9eQpDT05GSUdfUlBNU0dfVklSVElPPXkKIyBlbmQgb2YgUnBt
c2cgZHJpdmVycwoKIwojIFNPQyAoU3lzdGVtIE9uIENoaXApIHNwZWNpZmljIERyaXZlcnMK
IwoKIwojIEFtbG9naWMgU29DIGRyaXZlcnMKIwojIGVuZCBvZiBBbWxvZ2ljIFNvQyBkcml2
ZXJzCgojCiMgQXNwZWVkIFNvQyBkcml2ZXJzCiMKIyBlbmQgb2YgQXNwZWVkIFNvQyBkcml2
ZXJzCgojCiMgQnJvYWRjb20gU29DIGRyaXZlcnMKIwojIGVuZCBvZiBCcm9hZGNvbSBTb0Mg
ZHJpdmVycwoKIwojIE5YUC9GcmVlc2NhbGUgUW9ySVEgU29DIGRyaXZlcnMKIwojIGVuZCBv
ZiBOWFAvRnJlZXNjYWxlIFFvcklRIFNvQyBkcml2ZXJzCgojCiMgaS5NWCBTb0MgZHJpdmVy
cwojCiMgZW5kIG9mIGkuTVggU29DIGRyaXZlcnMKCiMKIyBRdWFsY29tbSBTb0MgZHJpdmVy
cwojCiMgZW5kIG9mIFF1YWxjb21tIFNvQyBkcml2ZXJzCgojIENPTkZJR19TT0NfVEkgaXMg
bm90IHNldAoKIwojIFhpbGlueCBTb0MgZHJpdmVycwojCkNPTkZJR19YSUxJTlhfVkNVPXkK
IyBlbmQgb2YgWGlsaW54IFNvQyBkcml2ZXJzCiMgZW5kIG9mIFNPQyAoU3lzdGVtIE9uIENo
aXApIHNwZWNpZmljIERyaXZlcnMKCiMgQ09ORklHX1BNX0RFVkZSRVEgaXMgbm90IHNldAoj
IENPTkZJR19FWFRDT04gaXMgbm90IHNldAojIENPTkZJR19NRU1PUlkgaXMgbm90IHNldApD
T05GSUdfSUlPPXkKQ09ORklHX0lJT19CVUZGRVI9eQpDT05GSUdfSUlPX0JVRkZFUl9DQj15
CkNPTkZJR19JSU9fQlVGRkVSX0hXX0NPTlNVTUVSPW0KQ09ORklHX0lJT19LRklGT19CVUY9
eQpDT05GSUdfSUlPX1RSSUdHRVJFRF9CVUZGRVI9eQpDT05GSUdfSUlPX0NPTkZJR0ZTPXkK
Q09ORklHX0lJT19UUklHR0VSPXkKQ09ORklHX0lJT19DT05TVU1FUlNfUEVSX1RSSUdHRVI9
MgojIENPTkZJR19JSU9fU1dfREVWSUNFIGlzIG5vdCBzZXQKIyBDT05GSUdfSUlPX1NXX1RS
SUdHRVIgaXMgbm90IHNldAoKIwojIEFjY2VsZXJvbWV0ZXJzCiMKIyBDT05GSUdfQURJUzE2
MjAxIGlzIG5vdCBzZXQKIyBDT05GSUdfQURJUzE2MjA5IGlzIG5vdCBzZXQKQ09ORklHX0FE
WEwzNDU9eQpDT05GSUdfQURYTDM0NV9JMkM9eQojIENPTkZJR19BRFhMMzQ1X1NQSSBpcyBu
b3Qgc2V0CkNPTkZJR19BRFhMMzcyPXkKQ09ORklHX0FEWEwzNzJfU1BJPXkKQ09ORklHX0FE
WEwzNzJfSTJDPXkKQ09ORklHX0JNQTE4MD15CiMgQ09ORklHX0JNQTIyMCBpcyBub3Qgc2V0
CkNPTkZJR19CTUMxNTBfQUNDRUw9eQpDT05GSUdfQk1DMTUwX0FDQ0VMX0kyQz15CkNPTkZJ
R19CTUMxNTBfQUNDRUxfU1BJPXkKIyBDT05GSUdfREEyODAgaXMgbm90IHNldApDT05GSUdf
REEzMTE9bQpDT05GSUdfRE1BUkQwOT1tCiMgQ09ORklHX0RNQVJEMTAgaXMgbm90IHNldApD
T05GSUdfSUlPX0NST1NfRUNfQUNDRUxfTEVHQUNZPW0KIyBDT05GSUdfSUlPX1NUX0FDQ0VM
XzNBWElTIGlzIG5vdCBzZXQKQ09ORklHX0tYU0Q5PW0KIyBDT05GSUdfS1hTRDlfU1BJIGlz
IG5vdCBzZXQKQ09ORklHX0tYU0Q5X0kyQz1tCkNPTkZJR19LWENKSzEwMTM9bQojIENPTkZJ
R19NQzMyMzAgaXMgbm90IHNldApDT05GSUdfTU1BNzQ1NT1tCiMgQ09ORklHX01NQTc0NTVf
STJDIGlzIG5vdCBzZXQKQ09ORklHX01NQTc0NTVfU1BJPW0KIyBDT05GSUdfTU1BNzY2MCBp
cyBub3Qgc2V0CiMgQ09ORklHX01NQTg0NTIgaXMgbm90IHNldAojIENPTkZJR19NTUE5NTUx
IGlzIG5vdCBzZXQKIyBDT05GSUdfTU1BOTU1MyBpcyBub3Qgc2V0CkNPTkZJR19NWEM0MDA1
PW0KQ09ORklHX01YQzYyNTU9eQojIENPTkZJR19TQ0EzMDAwIGlzIG5vdCBzZXQKQ09ORklH
X1NUSzgzMTI9bQpDT05GSUdfU1RLOEJBNTA9bQojIGVuZCBvZiBBY2NlbGVyb21ldGVycwoK
IwojIEFuYWxvZyB0byBkaWdpdGFsIGNvbnZlcnRlcnMKIwpDT05GSUdfQURfU0lHTUFfREVM
VEE9eQojIENPTkZJR19BRDcxMjQgaXMgbm90IHNldApDT05GSUdfQUQ3MjY2PXkKQ09ORklH
X0FENzI5MT1tCiMgQ09ORklHX0FENzI5MiBpcyBub3Qgc2V0CkNPTkZJR19BRDcyOTg9bQpD
T05GSUdfQUQ3NDc2PXkKQ09ORklHX0FENzYwNj15CkNPTkZJR19BRDc2MDZfSUZBQ0VfUEFS
QUxMRUw9bQpDT05GSUdfQUQ3NjA2X0lGQUNFX1NQST15CkNPTkZJR19BRDc3NjY9eQpDT05G
SUdfQUQ3NzY4XzE9bQojIENPTkZJR19BRDc3ODAgaXMgbm90IHNldApDT05GSUdfQUQ3Nzkx
PXkKIyBDT05GSUdfQUQ3NzkzIGlzIG5vdCBzZXQKIyBDT05GSUdfQUQ3ODg3IGlzIG5vdCBz
ZXQKQ09ORklHX0FENzkyMz15CiMgQ09ORklHX0FENzk0OSBpcyBub3Qgc2V0CkNPTkZJR19B
RDc5OVg9eQpDT05GSUdfQVhQMjBYX0FEQz1tCkNPTkZJR19BWFAyODhfQURDPW0KIyBDT05G
SUdfSEk4NDM1IGlzIG5vdCBzZXQKIyBDT05GSUdfSFg3MTEgaXMgbm90IHNldApDT05GSUdf
TFRDMjQ3MT15CkNPTkZJR19MVEMyNDg1PW0KQ09ORklHX0xUQzI0OTc9eQojIENPTkZJR19N
QVgxMDI3IGlzIG5vdCBzZXQKQ09ORklHX01BWDExMTAwPW0KQ09ORklHX01BWDExMTg9bQoj
IENPTkZJR19NQVgxMzYzIGlzIG5vdCBzZXQKQ09ORklHX01BWDk2MTE9eQojIENPTkZJR19N
Q1AzMjBYIGlzIG5vdCBzZXQKQ09ORklHX01DUDM0MjI9bQpDT05GSUdfTUNQMzkxMT1tCkNP
TkZJR19NRU5fWjE4OF9BREM9bQojIENPTkZJR19OQVU3ODAyIGlzIG5vdCBzZXQKQ09ORklH
X1BBTE1BU19HUEFEQz1tCkNPTkZJR19USV9BREMwODFDPXkKIyBDT05GSUdfVElfQURDMDgz
MiBpcyBub3Qgc2V0CiMgQ09ORklHX1RJX0FEQzA4NFMwMjEgaXMgbm90IHNldApDT05GSUdf
VElfQURDMTIxMzg9eQpDT05GSUdfVElfQURDMTA4UzEwMj15CkNPTkZJR19USV9BREMxMjhT
MDUyPW0KQ09ORklHX1RJX0FEQzE2MVM2MjY9bQpDT05GSUdfVElfQURTMTAxNT1tCkNPTkZJ
R19USV9BRFM3OTUwPW0KQ09ORklHX1RJX0FNMzM1WF9BREM9eQpDT05GSUdfVElfVExDNDU0
MT1tCiMgQ09ORklHX1hJTElOWF9YQURDIGlzIG5vdCBzZXQKIyBlbmQgb2YgQW5hbG9nIHRv
IGRpZ2l0YWwgY29udmVydGVycwoKIwojIEFuYWxvZyBGcm9udCBFbmRzCiMKIyBlbmQgb2Yg
QW5hbG9nIEZyb250IEVuZHMKCiMKIyBBbXBsaWZpZXJzCiMKIyBDT05GSUdfQUQ4MzY2IGlz
IG5vdCBzZXQKIyBlbmQgb2YgQW1wbGlmaWVycwoKIwojIENoZW1pY2FsIFNlbnNvcnMKIwpD
T05GSUdfQVRMQVNfUEhfU0VOU09SPW0KQ09ORklHX0JNRTY4MD15CkNPTkZJR19CTUU2ODBf
STJDPXkKQ09ORklHX0JNRTY4MF9TUEk9eQpDT05GSUdfQ0NTODExPW0KIyBDT05GSUdfSUFR
Q09SRSBpcyBub3Qgc2V0CkNPTkZJR19TRU5TSVJJT05fU0dQMzA9bQpDT05GSUdfU1BTMzA9
eQojIENPTkZJR19WWjg5WCBpcyBub3Qgc2V0CiMgZW5kIG9mIENoZW1pY2FsIFNlbnNvcnMK
CkNPTkZJR19JSU9fQ1JPU19FQ19TRU5TT1JTX0NPUkU9bQpDT05GSUdfSUlPX0NST1NfRUNf
U0VOU09SUz1tCiMgQ09ORklHX0lJT19DUk9TX0VDX1NFTlNPUlNfTElEX0FOR0xFIGlzIG5v
dCBzZXQKCiMKIyBIaWQgU2Vuc29yIElJTyBDb21tb24KIwojIGVuZCBvZiBIaWQgU2Vuc29y
IElJTyBDb21tb24KCkNPTkZJR19JSU9fTVNfU0VOU09SU19JMkM9eQoKIwojIFNTUCBTZW5z
b3IgQ29tbW9uCiMKQ09ORklHX0lJT19TU1BfU0VOU09SU19DT01NT05TPW0KQ09ORklHX0lJ
T19TU1BfU0VOU09SSFVCPXkKIyBlbmQgb2YgU1NQIFNlbnNvciBDb21tb24KCkNPTkZJR19J
SU9fU1RfU0VOU09SU19JMkM9eQpDT05GSUdfSUlPX1NUX1NFTlNPUlNfU1BJPXkKQ09ORklH
X0lJT19TVF9TRU5TT1JTX0NPUkU9eQoKIwojIERpZ2l0YWwgdG8gYW5hbG9nIGNvbnZlcnRl
cnMKIwpDT05GSUdfQUQ1MDY0PW0KQ09ORklHX0FENTM2MD1tCkNPTkZJR19BRDUzODA9bQpD
T05GSUdfQUQ1NDIxPXkKIyBDT05GSUdfQUQ1NDQ2IGlzIG5vdCBzZXQKQ09ORklHX0FENTQ0
OT1tCkNPTkZJR19BRDU1OTJSX0JBU0U9bQpDT05GSUdfQUQ1NTkyUj1tCiMgQ09ORklHX0FE
NTU5M1IgaXMgbm90IHNldAojIENPTkZJR19BRDU1MDQgaXMgbm90IHNldAojIENPTkZJR19B
RDU2MjRSX1NQSSBpcyBub3Qgc2V0CkNPTkZJR19MVEMxNjYwPXkKQ09ORklHX0xUQzI2MzI9
bQpDT05GSUdfQUQ1Njg2PW0KQ09ORklHX0FENTY4Nl9TUEk9bQojIENPTkZJR19BRDU2OTZf
STJDIGlzIG5vdCBzZXQKQ09ORklHX0FENTc1NT15CkNPTkZJR19BRDU3NTg9eQpDT05GSUdf
QUQ1NzYxPXkKQ09ORklHX0FENTc2ND15CkNPTkZJR19BRDU3OTE9bQojIENPTkZJR19BRDcz
MDMgaXMgbm90IHNldApDT05GSUdfQUQ4ODAxPXkKIyBDT05GSUdfRFM0NDI0IGlzIG5vdCBz
ZXQKQ09ORklHX002MjMzMj1tCkNPTkZJR19NQVg1MTc9bQpDT05GSUdfTUNQNDcyNT1tCkNP
TkZJR19NQ1A0OTIyPXkKQ09ORklHX1RJX0RBQzA4MlMwODU9eQpDT05GSUdfVElfREFDNTU3
MT1tCkNPTkZJR19USV9EQUM3MzExPXkKIyBDT05GSUdfVElfREFDNzYxMiBpcyBub3Qgc2V0
CiMgZW5kIG9mIERpZ2l0YWwgdG8gYW5hbG9nIGNvbnZlcnRlcnMKCiMKIyBJSU8gZHVtbXkg
ZHJpdmVyCiMKIyBlbmQgb2YgSUlPIGR1bW15IGRyaXZlcgoKIwojIEZyZXF1ZW5jeSBTeW50
aGVzaXplcnMgRERTL1BMTAojCgojCiMgQ2xvY2sgR2VuZXJhdG9yL0Rpc3RyaWJ1dGlvbgoj
CkNPTkZJR19BRDk1MjM9eQojIGVuZCBvZiBDbG9jayBHZW5lcmF0b3IvRGlzdHJpYnV0aW9u
CgojCiMgUGhhc2UtTG9ja2VkIExvb3AgKFBMTCkgZnJlcXVlbmN5IHN5bnRoZXNpemVycwoj
CkNPTkZJR19BREY0MzUwPW0KQ09ORklHX0FERjQzNzE9eQojIGVuZCBvZiBQaGFzZS1Mb2Nr
ZWQgTG9vcCAoUExMKSBmcmVxdWVuY3kgc3ludGhlc2l6ZXJzCiMgZW5kIG9mIEZyZXF1ZW5j
eSBTeW50aGVzaXplcnMgRERTL1BMTAoKIwojIERpZ2l0YWwgZ3lyb3Njb3BlIHNlbnNvcnMK
IwpDT05GSUdfQURJUzE2MDgwPXkKIyBDT05GSUdfQURJUzE2MTMwIGlzIG5vdCBzZXQKIyBD
T05GSUdfQURJUzE2MTM2IGlzIG5vdCBzZXQKIyBDT05GSUdfQURJUzE2MjYwIGlzIG5vdCBz
ZXQKIyBDT05GSUdfQURYUlM0NTAgaXMgbm90IHNldApDT05GSUdfQk1HMTYwPXkKQ09ORklH
X0JNRzE2MF9JMkM9eQpDT05GSUdfQk1HMTYwX1NQST15CiMgQ09ORklHX0ZYQVMyMTAwMkMg
aXMgbm90IHNldAojIENPTkZJR19NUFUzMDUwX0kyQyBpcyBub3Qgc2V0CiMgQ09ORklHX0lJ
T19TVF9HWVJPXzNBWElTIGlzIG5vdCBzZXQKIyBDT05GSUdfSVRHMzIwMCBpcyBub3Qgc2V0
CiMgZW5kIG9mIERpZ2l0YWwgZ3lyb3Njb3BlIHNlbnNvcnMKCiMKIyBIZWFsdGggU2Vuc29y
cwojCgojCiMgSGVhcnQgUmF0ZSBNb25pdG9ycwojCkNPTkZJR19BRkU0NDAzPXkKIyBDT05G
SUdfQUZFNDQwNCBpcyBub3Qgc2V0CkNPTkZJR19NQVgzMDEwMD1tCiMgQ09ORklHX01BWDMw
MTAyIGlzIG5vdCBzZXQKIyBlbmQgb2YgSGVhcnQgUmF0ZSBNb25pdG9ycwojIGVuZCBvZiBI
ZWFsdGggU2Vuc29ycwoKIwojIEh1bWlkaXR5IHNlbnNvcnMKIwojIENPTkZJR19BTTIzMTUg
aXMgbm90IHNldApDT05GSUdfREhUMTE9bQojIENPTkZJR19IREMxMDBYIGlzIG5vdCBzZXQK
Q09ORklHX0hUUzIyMT15CkNPTkZJR19IVFMyMjFfSTJDPXkKQ09ORklHX0hUUzIyMV9TUEk9
eQpDT05GSUdfSFRVMjE9eQojIENPTkZJR19TSTcwMDUgaXMgbm90IHNldAojIENPTkZJR19T
STcwMjAgaXMgbm90IHNldAojIGVuZCBvZiBIdW1pZGl0eSBzZW5zb3JzCgojCiMgSW5lcnRp
YWwgbWVhc3VyZW1lbnQgdW5pdHMKIwojIENPTkZJR19BRElTMTY0MDAgaXMgbm90IHNldApD
T05GSUdfQURJUzE2NDYwPW0KQ09ORklHX0FESVMxNjQ4MD15CkNPTkZJR19CTUkxNjA9bQpD
T05GSUdfQk1JMTYwX0kyQz1tCkNPTkZJR19CTUkxNjBfU1BJPW0KIyBDT05GSUdfRlhPUzg3
MDBfSTJDIGlzIG5vdCBzZXQKIyBDT05GSUdfRlhPUzg3MDBfU1BJIGlzIG5vdCBzZXQKQ09O
RklHX0tNWDYxPXkKQ09ORklHX0lOVl9NUFU2MDUwX0lJTz1tCkNPTkZJR19JTlZfTVBVNjA1
MF9JMkM9bQpDT05GSUdfSU5WX01QVTYwNTBfU1BJPW0KQ09ORklHX0lJT19TVF9MU002RFNY
PW0KQ09ORklHX0lJT19TVF9MU002RFNYX0kyQz1tCkNPTkZJR19JSU9fU1RfTFNNNkRTWF9T
UEk9bQojIGVuZCBvZiBJbmVydGlhbCBtZWFzdXJlbWVudCB1bml0cwoKQ09ORklHX0lJT19B
RElTX0xJQj15CkNPTkZJR19JSU9fQURJU19MSUJfQlVGRkVSPXkKCiMKIyBMaWdodCBzZW5z
b3JzCiMKIyBDT05GSUdfQURKRF9TMzExIGlzIG5vdCBzZXQKQ09ORklHX0FEVVgxMDIwPW0K
Q09ORklHX0FMMzMyMEE9bQpDT05GSUdfQVBEUzkzMDA9bQpDT05GSUdfQVBEUzk5NjA9bQoj
IENPTkZJR19CSDE3NTAgaXMgbm90IHNldApDT05GSUdfQkgxNzgwPXkKQ09ORklHX0NNMzIx
ODE9eQojIENPTkZJR19DTTMyMzIgaXMgbm90IHNldApDT05GSUdfQ00zMzIzPW0KQ09ORklH
X0NNMzY2NTE9bQojIENPTkZJR19JSU9fQ1JPU19FQ19MSUdIVF9QUk9YIGlzIG5vdCBzZXQK
IyBDT05GSUdfR1AyQVAwMjBBMDBGIGlzIG5vdCBzZXQKIyBDT05GSUdfU0VOU09SU19JU0wy
OTAxOCBpcyBub3Qgc2V0CkNPTkZJR19TRU5TT1JTX0lTTDI5MDI4PW0KQ09ORklHX0lTTDI5
MTI1PW0KQ09ORklHX0pTQTEyMTI9eQojIENPTkZJR19SUFIwNTIxIGlzIG5vdCBzZXQKIyBD
T05GSUdfU0VOU09SU19MTTM1MzMgaXMgbm90IHNldAojIENPTkZJR19MVFI1MDEgaXMgbm90
IHNldApDT05GSUdfTFYwMTA0Q1M9bQpDT05GSUdfTUFYNDQwMDA9bQpDT05GSUdfTUFYNDQw
MDk9bQojIENPTkZJR19OT0ExMzA1IGlzIG5vdCBzZXQKQ09ORklHX09QVDMwMDE9eQpDT05G
SUdfUEExMjIwMzAwMT1tCkNPTkZJR19TSTExMzM9bQpDT05GSUdfU0kxMTQ1PXkKIyBDT05G
SUdfU1RLMzMxMCBpcyBub3Qgc2V0CiMgQ09ORklHX1NUX1VWSVMyNSBpcyBub3Qgc2V0CkNP
TkZJR19UQ1MzNDE0PW0KIyBDT05GSUdfVENTMzQ3MiBpcyBub3Qgc2V0CkNPTkZJR19TRU5T
T1JTX1RTTDI1NjM9bQojIENPTkZJR19UU0wyNTgzIGlzIG5vdCBzZXQKQ09ORklHX1RTTDI3
NzI9bQpDT05GSUdfVFNMNDUzMT1tCkNPTkZJR19VUzUxODJEPW0KIyBDT05GSUdfVkNOTDQw
MDAgaXMgbm90IHNldApDT05GSUdfVkNOTDQwMzU9bQpDT05GSUdfVkVNTDYwMzA9eQpDT05G
SUdfVkVNTDYwNzA9eQojIENPTkZJR19WTDYxODAgaXMgbm90IHNldApDT05GSUdfWk9QVDIy
MDE9eQojIGVuZCBvZiBMaWdodCBzZW5zb3JzCgojCiMgTWFnbmV0b21ldGVyIHNlbnNvcnMK
IwpDT05GSUdfQUs4OTc1PW0KIyBDT05GSUdfQUswOTkxMSBpcyBub3Qgc2V0CkNPTkZJR19C
TUMxNTBfTUFHTj1tCkNPTkZJR19CTUMxNTBfTUFHTl9JMkM9bQojIENPTkZJR19CTUMxNTBf
TUFHTl9TUEkgaXMgbm90IHNldApDT05GSUdfTUFHMzExMD15CkNPTkZJR19NTUMzNTI0MD15
CkNPTkZJR19JSU9fU1RfTUFHTl8zQVhJUz1tCkNPTkZJR19JSU9fU1RfTUFHTl9JMkNfM0FY
SVM9bQpDT05GSUdfSUlPX1NUX01BR05fU1BJXzNBWElTPW0KQ09ORklHX1NFTlNPUlNfSE1D
NTg0Mz15CkNPTkZJR19TRU5TT1JTX0hNQzU4NDNfSTJDPXkKQ09ORklHX1NFTlNPUlNfSE1D
NTg0M19TUEk9bQpDT05GSUdfU0VOU09SU19STTMxMDA9eQpDT05GSUdfU0VOU09SU19STTMx
MDBfSTJDPXkKIyBDT05GSUdfU0VOU09SU19STTMxMDBfU1BJIGlzIG5vdCBzZXQKIyBlbmQg
b2YgTWFnbmV0b21ldGVyIHNlbnNvcnMKCiMKIyBNdWx0aXBsZXhlcnMKIwojIGVuZCBvZiBN
dWx0aXBsZXhlcnMKCiMKIyBJbmNsaW5vbWV0ZXIgc2Vuc29ycwojCiMgZW5kIG9mIEluY2xp
bm9tZXRlciBzZW5zb3JzCgojCiMgVHJpZ2dlcnMgLSBzdGFuZGFsb25lCiMKIyBDT05GSUdf
SUlPX0lOVEVSUlVQVF9UUklHR0VSIGlzIG5vdCBzZXQKQ09ORklHX0lJT19TWVNGU19UUklH
R0VSPW0KIyBlbmQgb2YgVHJpZ2dlcnMgLSBzdGFuZGFsb25lCgojCiMgRGlnaXRhbCBwb3Rl
bnRpb21ldGVycwojCkNPTkZJR19BRDUyNzI9bQojIENPTkZJR19EUzE4MDMgaXMgbm90IHNl
dApDT05GSUdfTUFYNTQzMj1tCiMgQ09ORklHX01BWDU0ODEgaXMgbm90IHNldAojIENPTkZJ
R19NQVg1NDg3IGlzIG5vdCBzZXQKIyBDT05GSUdfTUNQNDAxOCBpcyBub3Qgc2V0CkNPTkZJ
R19NQ1A0MTMxPXkKIyBDT05GSUdfTUNQNDUzMSBpcyBub3Qgc2V0CkNPTkZJR19NQ1A0MTAx
MD15CkNPTkZJR19UUEwwMTAyPW0KIyBlbmQgb2YgRGlnaXRhbCBwb3RlbnRpb21ldGVycwoK
IwojIERpZ2l0YWwgcG90ZW50aW9zdGF0cwojCiMgQ09ORklHX0xNUDkxMDAwIGlzIG5vdCBz
ZXQKIyBlbmQgb2YgRGlnaXRhbCBwb3RlbnRpb3N0YXRzCgojCiMgUHJlc3N1cmUgc2Vuc29y
cwojCkNPTkZJR19BQlAwNjBNRz1tCkNPTkZJR19CTVAyODA9eQpDT05GSUdfQk1QMjgwX0ky
Qz15CkNPTkZJR19CTVAyODBfU1BJPXkKQ09ORklHX0lJT19DUk9TX0VDX0JBUk89bQpDT05G
SUdfRFBTMzEwPXkKIyBDT05GSUdfSFAwMyBpcyBub3Qgc2V0CkNPTkZJR19NUEwxMTU9bQpD
T05GSUdfTVBMMTE1X0kyQz1tCiMgQ09ORklHX01QTDExNV9TUEkgaXMgbm90IHNldApDT05G
SUdfTVBMMzExNT1tCkNPTkZJR19NUzU2MTE9eQpDT05GSUdfTVM1NjExX0kyQz1tCkNPTkZJ
R19NUzU2MTFfU1BJPW0KIyBDT05GSUdfTVM1NjM3IGlzIG5vdCBzZXQKQ09ORklHX0lJT19T
VF9QUkVTUz15CkNPTkZJR19JSU9fU1RfUFJFU1NfSTJDPXkKQ09ORklHX0lJT19TVF9QUkVT
U19TUEk9eQpDT05GSUdfVDU0MDM9bQojIENPTkZJR19IUDIwNkMgaXMgbm90IHNldApDT05G
SUdfWlBBMjMyNj1tCkNPTkZJR19aUEEyMzI2X0kyQz1tCkNPTkZJR19aUEEyMzI2X1NQST1t
CiMgZW5kIG9mIFByZXNzdXJlIHNlbnNvcnMKCiMKIyBMaWdodG5pbmcgc2Vuc29ycwojCiMg
Q09ORklHX0FTMzkzNSBpcyBub3Qgc2V0CiMgZW5kIG9mIExpZ2h0bmluZyBzZW5zb3JzCgoj
CiMgUHJveGltaXR5IGFuZCBkaXN0YW5jZSBzZW5zb3JzCiMKQ09ORklHX0lTTDI5NTAxPW0K
Q09ORklHX0xJREFSX0xJVEVfVjI9eQojIENPTkZJR19NQjEyMzIgaXMgbm90IHNldApDT05G
SUdfUkZENzc0MDI9eQpDT05GSUdfU1JGMDQ9bQpDT05GSUdfU1g5NTAwPXkKIyBDT05GSUdf
U1JGMDggaXMgbm90IHNldAojIENPTkZJR19WTDUzTDBYX0kyQyBpcyBub3Qgc2V0CiMgZW5k
IG9mIFByb3hpbWl0eSBhbmQgZGlzdGFuY2Ugc2Vuc29ycwoKIwojIFJlc29sdmVyIHRvIGRp
Z2l0YWwgY29udmVydGVycwojCkNPTkZJR19BRDJTOTA9eQpDT05GSUdfQUQyUzEyMDA9bQoj
IGVuZCBvZiBSZXNvbHZlciB0byBkaWdpdGFsIGNvbnZlcnRlcnMKCiMKIyBUZW1wZXJhdHVy
ZSBzZW5zb3JzCiMKQ09ORklHX0xUQzI5ODM9eQojIENPTkZJR19NQVhJTV9USEVSTU9DT1VQ
TEUgaXMgbm90IHNldApDT05GSUdfTUxYOTA2MTQ9eQojIENPTkZJR19NTFg5MDYzMiBpcyBu
b3Qgc2V0CiMgQ09ORklHX1RNUDAwNiBpcyBub3Qgc2V0CkNPTkZJR19UTVAwMDc9eQpDT05G
SUdfVFNZUzAxPXkKQ09ORklHX1RTWVMwMkQ9eQojIENPTkZJR19NQVgzMTg1NiBpcyBub3Qg
c2V0CiMgZW5kIG9mIFRlbXBlcmF0dXJlIHNlbnNvcnMKCiMgQ09ORklHX1BXTSBpcyBub3Qg
c2V0CgojCiMgSVJRIGNoaXAgc3VwcG9ydAojCkNPTkZJR19NQURFUkFfSVJRPW0KIyBlbmQg
b2YgSVJRIGNoaXAgc3VwcG9ydAoKIyBDT05GSUdfSVBBQ0tfQlVTIGlzIG5vdCBzZXQKQ09O
RklHX1JFU0VUX0NPTlRST0xMRVI9eQojIENPTkZJR19SRVNFVF9USV9TWVNDT04gaXMgbm90
IHNldAoKIwojIFBIWSBTdWJzeXN0ZW0KIwpDT05GSUdfR0VORVJJQ19QSFk9eQpDT05GSUdf
QkNNX0tPTkFfVVNCMl9QSFk9eQpDT05GSUdfUEhZX1BYQV8yOE5NX0hTSUM9bQpDT05GSUdf
UEhZX1BYQV8yOE5NX1VTQjI9eQojIGVuZCBvZiBQSFkgU3Vic3lzdGVtCgojIENPTkZJR19Q
T1dFUkNBUCBpcyBub3Qgc2V0CkNPTkZJR19NQ0I9bQpDT05GSUdfTUNCX0xQQz1tCgojCiMg
UGVyZm9ybWFuY2UgbW9uaXRvciBzdXBwb3J0CiMKIyBlbmQgb2YgUGVyZm9ybWFuY2UgbW9u
aXRvciBzdXBwb3J0CgpDT05GSUdfUkFTPXkKCiMKIyBBbmRyb2lkCiMKQ09ORklHX0FORFJP
SUQ9eQojIENPTkZJR19BTkRST0lEX0JJTkRFUl9JUEMgaXMgbm90IHNldAojIGVuZCBvZiBB
bmRyb2lkCgpDT05GSUdfREFYPXkKQ09ORklHX05WTUVNPXkKQ09ORklHX05WTUVNX1NZU0ZT
PXkKCiMKIyBIVyB0cmFjaW5nIHN1cHBvcnQKIwojIENPTkZJR19TVE0gaXMgbm90IHNldApD
T05GSUdfSU5URUxfVEg9eQpDT05GSUdfSU5URUxfVEhfR1RIPXkKQ09ORklHX0lOVEVMX1RI
X01TVT1tCkNPTkZJR19JTlRFTF9USF9QVEk9bQojIENPTkZJR19JTlRFTF9USF9ERUJVRyBp
cyBub3Qgc2V0CiMgZW5kIG9mIEhXIHRyYWNpbmcgc3VwcG9ydAoKIyBDT05GSUdfRlBHQSBp
cyBub3Qgc2V0CkNPTkZJR19TSU9YPW0KQ09ORklHX1NJT1hfQlVTX0dQSU89bQpDT05GSUdf
U0xJTUJVUz1tCkNPTkZJR19TTElNX1FDT01fQ1RSTD1tCkNPTkZJR19JTlRFUkNPTk5FQ1Q9
eQojIENPTkZJR19DT1VOVEVSIGlzIG5vdCBzZXQKIyBlbmQgb2YgRGV2aWNlIERyaXZlcnMK
CiMKIyBGaWxlIHN5c3RlbXMKIwpDT05GSUdfRENBQ0hFX1dPUkRfQUNDRVNTPXkKQ09ORklH
X1ZBTElEQVRFX0ZTX1BBUlNFUj15CkNPTkZJR19GU19QT1NJWF9BQ0w9eQpDT05GSUdfRVhQ
T1JURlM9bQojIENPTkZJR19FWFBPUlRGU19CTE9DS19PUFMgaXMgbm90IHNldAojIENPTkZJ
R19GSUxFX0xPQ0tJTkcgaXMgbm90IHNldAojIENPTkZJR19GU19FTkNSWVBUSU9OIGlzIG5v
dCBzZXQKQ09ORklHX0ZTX1ZFUklUWT15CkNPTkZJR19GU19WRVJJVFlfREVCVUc9eQojIENP
TkZJR19GU19WRVJJVFlfQlVJTFRJTl9TSUdOQVRVUkVTIGlzIG5vdCBzZXQKQ09ORklHX0ZT
Tk9USUZZPXkKIyBDT05GSUdfRE5PVElGWSBpcyBub3Qgc2V0CkNPTkZJR19JTk9USUZZX1VT
RVI9eQojIENPTkZJR19GQU5PVElGWSBpcyBub3Qgc2V0CiMgQ09ORklHX1FVT1RBIGlzIG5v
dCBzZXQKQ09ORklHX0FVVE9GUzRfRlM9bQpDT05GSUdfQVVUT0ZTX0ZTPW0KQ09ORklHX0ZV
U0VfRlM9eQpDT05GSUdfQ1VTRT1tCkNPTkZJR19WSVJUSU9fRlM9eQpDT05GSUdfT1ZFUkxB
WV9GUz1tCkNPTkZJR19PVkVSTEFZX0ZTX1JFRElSRUNUX0RJUj15CiMgQ09ORklHX09WRVJM
QVlfRlNfUkVESVJFQ1RfQUxXQVlTX0ZPTExPVyBpcyBub3Qgc2V0CiMgQ09ORklHX09WRVJM
QVlfRlNfSU5ERVggaXMgbm90IHNldAojIENPTkZJR19PVkVSTEFZX0ZTX1hJTk9fQVVUTyBp
cyBub3Qgc2V0CiMgQ09ORklHX09WRVJMQVlfRlNfTUVUQUNPUFkgaXMgbm90IHNldAoKIwoj
IENhY2hlcwojCiMgQ09ORklHX0ZTQ0FDSEUgaXMgbm90IHNldAojIGVuZCBvZiBDYWNoZXMK
CiMKIyBQc2V1ZG8gZmlsZXN5c3RlbXMKIwojIENPTkZJR19QUk9DX0ZTIGlzIG5vdCBzZXQK
Q09ORklHX1BST0NfQ0hJTERSRU49eQpDT05GSUdfS0VSTkZTPXkKQ09ORklHX1NZU0ZTPXkK
Q09ORklHX1RNUEZTPXkKIyBDT05GSUdfVE1QRlNfUE9TSVhfQUNMIGlzIG5vdCBzZXQKQ09O
RklHX1RNUEZTX1hBVFRSPXkKIyBDT05GSUdfSFVHRVRMQkZTIGlzIG5vdCBzZXQKQ09ORklH
X01FTUZEX0NSRUFURT15CkNPTkZJR19BUkNIX0hBU19HSUdBTlRJQ19QQUdFPXkKQ09ORklH
X0NPTkZJR0ZTX0ZTPXkKIyBlbmQgb2YgUHNldWRvIGZpbGVzeXN0ZW1zCgojIENPTkZJR19N
SVNDX0ZJTEVTWVNURU1TIGlzIG5vdCBzZXQKQ09ORklHX05MUz1tCkNPTkZJR19OTFNfREVG
QVVMVD0iaXNvODg1OS0xIgojIENPTkZJR19OTFNfQ09ERVBBR0VfNDM3IGlzIG5vdCBzZXQK
Q09ORklHX05MU19DT0RFUEFHRV83Mzc9bQpDT05GSUdfTkxTX0NPREVQQUdFXzc3NT1tCiMg
Q09ORklHX05MU19DT0RFUEFHRV84NTAgaXMgbm90IHNldApDT05GSUdfTkxTX0NPREVQQUdF
Xzg1Mj1tCiMgQ09ORklHX05MU19DT0RFUEFHRV84NTUgaXMgbm90IHNldAojIENPTkZJR19O
TFNfQ09ERVBBR0VfODU3IGlzIG5vdCBzZXQKIyBDT05GSUdfTkxTX0NPREVQQUdFXzg2MCBp
cyBub3Qgc2V0CkNPTkZJR19OTFNfQ09ERVBBR0VfODYxPW0KIyBDT05GSUdfTkxTX0NPREVQ
QUdFXzg2MiBpcyBub3Qgc2V0CiMgQ09ORklHX05MU19DT0RFUEFHRV84NjMgaXMgbm90IHNl
dApDT05GSUdfTkxTX0NPREVQQUdFXzg2ND1tCkNPTkZJR19OTFNfQ09ERVBBR0VfODY1PW0K
Q09ORklHX05MU19DT0RFUEFHRV84NjY9bQojIENPTkZJR19OTFNfQ09ERVBBR0VfODY5IGlz
IG5vdCBzZXQKQ09ORklHX05MU19DT0RFUEFHRV85MzY9bQojIENPTkZJR19OTFNfQ09ERVBB
R0VfOTUwIGlzIG5vdCBzZXQKQ09ORklHX05MU19DT0RFUEFHRV85MzI9bQpDT05GSUdfTkxT
X0NPREVQQUdFXzk0OT1tCiMgQ09ORklHX05MU19DT0RFUEFHRV84NzQgaXMgbm90IHNldApD
T05GSUdfTkxTX0lTTzg4NTlfOD1tCiMgQ09ORklHX05MU19DT0RFUEFHRV8xMjUwIGlzIG5v
dCBzZXQKQ09ORklHX05MU19DT0RFUEFHRV8xMjUxPW0KQ09ORklHX05MU19BU0NJST1tCiMg
Q09ORklHX05MU19JU084ODU5XzEgaXMgbm90IHNldAojIENPTkZJR19OTFNfSVNPODg1OV8y
IGlzIG5vdCBzZXQKQ09ORklHX05MU19JU084ODU5XzM9bQojIENPTkZJR19OTFNfSVNPODg1
OV80IGlzIG5vdCBzZXQKIyBDT05GSUdfTkxTX0lTTzg4NTlfNSBpcyBub3Qgc2V0CiMgQ09O
RklHX05MU19JU084ODU5XzYgaXMgbm90IHNldApDT05GSUdfTkxTX0lTTzg4NTlfNz1tCiMg
Q09ORklHX05MU19JU084ODU5XzkgaXMgbm90IHNldAojIENPTkZJR19OTFNfSVNPODg1OV8x
MyBpcyBub3Qgc2V0CkNPTkZJR19OTFNfSVNPODg1OV8xND1tCkNPTkZJR19OTFNfSVNPODg1
OV8xNT1tCkNPTkZJR19OTFNfS09JOF9SPW0KIyBDT05GSUdfTkxTX0tPSThfVSBpcyBub3Qg
c2V0CiMgQ09ORklHX05MU19NQUNfUk9NQU4gaXMgbm90IHNldApDT05GSUdfTkxTX01BQ19D
RUxUSUM9bQpDT05GSUdfTkxTX01BQ19DRU5URVVSTz1tCiMgQ09ORklHX05MU19NQUNfQ1JP
QVRJQU4gaXMgbm90IHNldApDT05GSUdfTkxTX01BQ19DWVJJTExJQz1tCiMgQ09ORklHX05M
U19NQUNfR0FFTElDIGlzIG5vdCBzZXQKIyBDT05GSUdfTkxTX01BQ19HUkVFSyBpcyBub3Qg
c2V0CkNPTkZJR19OTFNfTUFDX0lDRUxBTkQ9bQpDT05GSUdfTkxTX01BQ19JTlVJVD1tCkNP
TkZJR19OTFNfTUFDX1JPTUFOSUFOPW0KQ09ORklHX05MU19NQUNfVFVSS0lTSD1tCiMgQ09O
RklHX05MU19VVEY4IGlzIG5vdCBzZXQKIyBDT05GSUdfVU5JQ09ERSBpcyBub3Qgc2V0CkNP
TkZJR19JT19XUT15CiMgZW5kIG9mIEZpbGUgc3lzdGVtcwoKIwojIFNlY3VyaXR5IG9wdGlv
bnMKIwpDT05GSUdfS0VZUz15CkNPTkZJR19LRVlTX0NPTVBBVD15CkNPTkZJR19LRVlTX1JF
UVVFU1RfQ0FDSEU9eQojIENPTkZJR19QRVJTSVNURU5UX0tFWVJJTkdTIGlzIG5vdCBzZXQK
Q09ORklHX0JJR19LRVlTPXkKQ09ORklHX1RSVVNURURfS0VZUz1tCkNPTkZJR19FTkNSWVBU
RURfS0VZUz15CkNPTkZJR19LRVlfREhfT1BFUkFUSU9OUz15CiMgQ09ORklHX0tFWV9OT1RJ
RklDQVRJT05TIGlzIG5vdCBzZXQKIyBDT05GSUdfU0VDVVJJVFlfRE1FU0dfUkVTVFJJQ1Qg
aXMgbm90IHNldAojIENPTkZJR19TRUNVUklUWSBpcyBub3Qgc2V0CiMgQ09ORklHX1NFQ1VS
SVRZRlMgaXMgbm90IHNldApDT05GSUdfUEFHRV9UQUJMRV9JU09MQVRJT049eQpDT05GSUdf
SEFWRV9IQVJERU5FRF9VU0VSQ09QWV9BTExPQ0FUT1I9eQpDT05GSUdfSEFSREVORURfVVNF
UkNPUFk9eQpDT05GSUdfSEFSREVORURfVVNFUkNPUFlfRkFMTEJBQ0s9eQojIENPTkZJR19I
QVJERU5FRF9VU0VSQ09QWV9QQUdFU1BBTiBpcyBub3Qgc2V0CiMgQ09ORklHX0ZPUlRJRllf
U09VUkNFIGlzIG5vdCBzZXQKIyBDT05GSUdfU1RBVElDX1VTRVJNT0RFSEVMUEVSIGlzIG5v
dCBzZXQKQ09ORklHX0RFRkFVTFRfU0VDVVJJVFlfREFDPXkKQ09ORklHX0xTTT0ibG9ja2Rv
d24seWFtYSxsb2FkcGluLHNhZmVzZXRpZCxpbnRlZ3JpdHkiCgojCiMgS2VybmVsIGhhcmRl
bmluZyBvcHRpb25zCiMKCiMKIyBNZW1vcnkgaW5pdGlhbGl6YXRpb24KIwpDT05GSUdfSU5J
VF9TVEFDS19OT05FPXkKQ09ORklHX0lOSVRfT05fQUxMT0NfREVGQVVMVF9PTj15CkNPTkZJ
R19JTklUX09OX0ZSRUVfREVGQVVMVF9PTj15CiMgZW5kIG9mIE1lbW9yeSBpbml0aWFsaXph
dGlvbgojIGVuZCBvZiBLZXJuZWwgaGFyZGVuaW5nIG9wdGlvbnMKIyBlbmQgb2YgU2VjdXJp
dHkgb3B0aW9ucwoKQ09ORklHX0NSWVBUTz15CgojCiMgQ3J5cHRvIGNvcmUgb3IgaGVscGVy
CiMKQ09ORklHX0NSWVBUT19BTEdBUEk9eQpDT05GSUdfQ1JZUFRPX0FMR0FQSTI9eQpDT05G
SUdfQ1JZUFRPX0FFQUQ9eQpDT05GSUdfQ1JZUFRPX0FFQUQyPXkKQ09ORklHX0NSWVBUT19T
S0NJUEhFUj15CkNPTkZJR19DUllQVE9fU0tDSVBIRVIyPXkKQ09ORklHX0NSWVBUT19IQVNI
PXkKQ09ORklHX0NSWVBUT19IQVNIMj15CkNPTkZJR19DUllQVE9fUk5HPXkKQ09ORklHX0NS
WVBUT19STkcyPXkKQ09ORklHX0NSWVBUT19STkdfREVGQVVMVD15CkNPTkZJR19DUllQVE9f
QUtDSVBIRVIyPXkKQ09ORklHX0NSWVBUT19BS0NJUEhFUj1tCkNPTkZJR19DUllQVE9fS1BQ
Mj15CkNPTkZJR19DUllQVE9fS1BQPXkKQ09ORklHX0NSWVBUT19BQ09NUDI9eQpDT05GSUdf
Q1JZUFRPX01BTkFHRVI9eQpDT05GSUdfQ1JZUFRPX01BTkFHRVIyPXkKQ09ORklHX0NSWVBU
T19NQU5BR0VSX0RJU0FCTEVfVEVTVFM9eQpDT05GSUdfQ1JZUFRPX0dGMTI4TVVMPXkKQ09O
RklHX0NSWVBUT19OVUxMPXkKQ09ORklHX0NSWVBUT19OVUxMMj15CkNPTkZJR19DUllQVE9f
UENSWVBUPW0KQ09ORklHX0NSWVBUT19DUllQVEQ9eQpDT05GSUdfQ1JZUFRPX0FVVEhFTkM9
bQpDT05GSUdfQ1JZUFRPX1RFU1Q9bQpDT05GSUdfQ1JZUFRPX1NJTUQ9eQpDT05GSUdfQ1JZ
UFRPX0dMVUVfSEVMUEVSX1g4Nj15CkNPTkZJR19DUllQVE9fRU5HSU5FPXkKCiMKIyBQdWJs
aWMta2V5IGNyeXB0b2dyYXBoeQojCiMgQ09ORklHX0NSWVBUT19SU0EgaXMgbm90IHNldApD
T05GSUdfQ1JZUFRPX0RIPXkKQ09ORklHX0NSWVBUT19FQ0M9eQpDT05GSUdfQ1JZUFRPX0VD
REg9eQpDT05GSUdfQ1JZUFRPX0VDUkRTQT1tCiMgQ09ORklHX0NSWVBUT19DVVJWRTI1NTE5
IGlzIG5vdCBzZXQKIyBDT05GSUdfQ1JZUFRPX0NVUlZFMjU1MTlfWDg2IGlzIG5vdCBzZXQK
CiMKIyBBdXRoZW50aWNhdGVkIEVuY3J5cHRpb24gd2l0aCBBc3NvY2lhdGVkIERhdGEKIwpD
T05GSUdfQ1JZUFRPX0NDTT15CkNPTkZJR19DUllQVE9fR0NNPXkKQ09ORklHX0NSWVBUT19D
SEFDSEEyMFBPTFkxMzA1PXkKIyBDT05GSUdfQ1JZUFRPX0FFR0lTMTI4IGlzIG5vdCBzZXQK
Q09ORklHX0NSWVBUT19BRUdJUzEyOF9BRVNOSV9TU0UyPXkKQ09ORklHX0NSWVBUT19TRVFJ
Vj15CkNPTkZJR19DUllQVE9fRUNIQUlOSVY9eQoKIwojIEJsb2NrIG1vZGVzCiMKQ09ORklH
X0NSWVBUT19DQkM9eQpDT05GSUdfQ1JZUFRPX0NGQj15CkNPTkZJR19DUllQVE9fQ1RSPXkK
Q09ORklHX0NSWVBUT19DVFM9eQpDT05GSUdfQ1JZUFRPX0VDQj15CkNPTkZJR19DUllQVE9f
TFJXPXkKQ09ORklHX0NSWVBUT19PRkI9bQpDT05GSUdfQ1JZUFRPX1BDQkM9eQpDT05GSUdf
Q1JZUFRPX1hUUz15CkNPTkZJR19DUllQVE9fS0VZV1JBUD15CkNPTkZJR19DUllQVE9fTkhQ
T0xZMTMwNT15CiMgQ09ORklHX0NSWVBUT19OSFBPTFkxMzA1X1NTRTIgaXMgbm90IHNldAoj
IENPTkZJR19DUllQVE9fTkhQT0xZMTMwNV9BVlgyIGlzIG5vdCBzZXQKQ09ORklHX0NSWVBU
T19BRElBTlRVTT15CkNPTkZJR19DUllQVE9fRVNTSVY9bQoKIwojIEhhc2ggbW9kZXMKIwpD
T05GSUdfQ1JZUFRPX0NNQUM9bQpDT05GSUdfQ1JZUFRPX0hNQUM9eQpDT05GSUdfQ1JZUFRP
X1hDQkM9eQpDT05GSUdfQ1JZUFRPX1ZNQUM9bQoKIwojIERpZ2VzdAojCkNPTkZJR19DUllQ
VE9fQ1JDMzJDPXkKQ09ORklHX0NSWVBUT19DUkMzMkNfSU5URUw9eQojIENPTkZJR19DUllQ
VE9fQ1JDMzIgaXMgbm90IHNldApDT05GSUdfQ1JZUFRPX0NSQzMyX1BDTE1VTD1tCkNPTkZJ
R19DUllQVE9fWFhIQVNIPW0KQ09ORklHX0NSWVBUT19CTEFLRTJCPXkKQ09ORklHX0NSWVBU
T19CTEFLRTJTPXkKQ09ORklHX0NSWVBUT19CTEFLRTJTX1g4Nj15CkNPTkZJR19DUllQVE9f
Q1JDVDEwRElGPW0KQ09ORklHX0NSWVBUT19DUkNUMTBESUZfUENMTVVMPW0KQ09ORklHX0NS
WVBUT19HSEFTSD15CkNPTkZJR19DUllQVE9fUE9MWTEzMDU9eQpDT05GSUdfQ1JZUFRPX1BP
TFkxMzA1X1g4Nl82ND15CkNPTkZJR19DUllQVE9fTUQ0PW0KQ09ORklHX0NSWVBUT19NRDU9
bQpDT05GSUdfQ1JZUFRPX01JQ0hBRUxfTUlDPW0KQ09ORklHX0NSWVBUT19STUQxMjg9bQpD
T05GSUdfQ1JZUFRPX1JNRDE2MD1tCkNPTkZJR19DUllQVE9fUk1EMjU2PW0KIyBDT05GSUdf
Q1JZUFRPX1JNRDMyMCBpcyBub3Qgc2V0CkNPTkZJR19DUllQVE9fU0hBMT15CkNPTkZJR19D
UllQVE9fU0hBMV9TU1NFMz15CkNPTkZJR19DUllQVE9fU0hBMjU2X1NTU0UzPW0KQ09ORklH
X0NSWVBUT19TSEE1MTJfU1NTRTM9eQpDT05GSUdfQ1JZUFRPX1NIQTI1Nj15CkNPTkZJR19D
UllQVE9fU0hBNTEyPXkKQ09ORklHX0NSWVBUT19TSEEzPW0KQ09ORklHX0NSWVBUT19TTTM9
bQpDT05GSUdfQ1JZUFRPX1NUUkVFQk9HPW0KQ09ORklHX0NSWVBUT19UR1IxOTI9eQpDT05G
SUdfQ1JZUFRPX1dQNTEyPW0KQ09ORklHX0NSWVBUT19HSEFTSF9DTE1VTF9OSV9JTlRFTD1t
CgojCiMgQ2lwaGVycwojCkNPTkZJR19DUllQVE9fQUVTPXkKIyBDT05GSUdfQ1JZUFRPX0FF
U19USSBpcyBub3Qgc2V0CkNPTkZJR19DUllQVE9fQUVTX05JX0lOVEVMPW0KQ09ORklHX0NS
WVBUT19BTlVCSVM9eQpDT05GSUdfQ1JZUFRPX0FSQzQ9bQpDT05GSUdfQ1JZUFRPX0JMT1dG
SVNIPW0KQ09ORklHX0NSWVBUT19CTE9XRklTSF9DT01NT049eQpDT05GSUdfQ1JZUFRPX0JM
T1dGSVNIX1g4Nl82ND15CkNPTkZJR19DUllQVE9fQ0FNRUxMSUE9eQpDT05GSUdfQ1JZUFRP
X0NBTUVMTElBX1g4Nl82ND15CkNPTkZJR19DUllQVE9fQ0FNRUxMSUFfQUVTTklfQVZYX1g4
Nl82ND15CkNPTkZJR19DUllQVE9fQ0FNRUxMSUFfQUVTTklfQVZYMl9YODZfNjQ9eQpDT05G
SUdfQ1JZUFRPX0NBU1RfQ09NTU9OPXkKQ09ORklHX0NSWVBUT19DQVNUNT1tCkNPTkZJR19D
UllQVE9fQ0FTVDVfQVZYX1g4Nl82ND1tCkNPTkZJR19DUllQVE9fQ0FTVDY9eQpDT05GSUdf
Q1JZUFRPX0NBU1Q2X0FWWF9YODZfNjQ9eQpDT05GSUdfQ1JZUFRPX0RFUz1tCkNPTkZJR19D
UllQVE9fREVTM19FREVfWDg2XzY0PXkKQ09ORklHX0NSWVBUT19GQ1JZUFQ9bQpDT05GSUdf
Q1JZUFRPX0tIQVpBRD15CiMgQ09ORklHX0NSWVBUT19TQUxTQTIwIGlzIG5vdCBzZXQKQ09O
RklHX0NSWVBUT19DSEFDSEEyMD15CkNPTkZJR19DUllQVE9fQ0hBQ0hBMjBfWDg2XzY0PXkK
Q09ORklHX0NSWVBUT19TRUVEPXkKQ09ORklHX0NSWVBUT19TRVJQRU5UPXkKIyBDT05GSUdf
Q1JZUFRPX1NFUlBFTlRfU1NFMl9YODZfNjQgaXMgbm90IHNldApDT05GSUdfQ1JZUFRPX1NF
UlBFTlRfQVZYX1g4Nl82ND15CkNPTkZJR19DUllQVE9fU0VSUEVOVF9BVlgyX1g4Nl82ND15
CkNPTkZJR19DUllQVE9fU000PW0KIyBDT05GSUdfQ1JZUFRPX1RFQSBpcyBub3Qgc2V0CiMg
Q09ORklHX0NSWVBUT19UV09GSVNIIGlzIG5vdCBzZXQKQ09ORklHX0NSWVBUT19UV09GSVNI
X0NPTU1PTj15CkNPTkZJR19DUllQVE9fVFdPRklTSF9YODZfNjQ9eQpDT05GSUdfQ1JZUFRP
X1RXT0ZJU0hfWDg2XzY0XzNXQVk9eQpDT05GSUdfQ1JZUFRPX1RXT0ZJU0hfQVZYX1g4Nl82
ND15CgojCiMgQ29tcHJlc3Npb24KIwpDT05GSUdfQ1JZUFRPX0RFRkxBVEU9bQojIENPTkZJ
R19DUllQVE9fTFpPIGlzIG5vdCBzZXQKQ09ORklHX0NSWVBUT184NDI9bQojIENPTkZJR19D
UllQVE9fTFo0IGlzIG5vdCBzZXQKQ09ORklHX0NSWVBUT19MWjRIQz1tCiMgQ09ORklHX0NS
WVBUT19aU1REIGlzIG5vdCBzZXQKCiMKIyBSYW5kb20gTnVtYmVyIEdlbmVyYXRpb24KIwoj
IENPTkZJR19DUllQVE9fQU5TSV9DUFJORyBpcyBub3Qgc2V0CkNPTkZJR19DUllQVE9fRFJC
R19NRU5VPXkKQ09ORklHX0NSWVBUT19EUkJHX0hNQUM9eQojIENPTkZJR19DUllQVE9fRFJC
R19IQVNIIGlzIG5vdCBzZXQKIyBDT05GSUdfQ1JZUFRPX0RSQkdfQ1RSIGlzIG5vdCBzZXQK
Q09ORklHX0NSWVBUT19EUkJHPXkKQ09ORklHX0NSWVBUT19KSVRURVJFTlRST1BZPXkKQ09O
RklHX0NSWVBUT19IQVNIX0lORk89eQoKIwojIENyeXB0byBsaWJyYXJ5IHJvdXRpbmVzCiMK
Q09ORklHX0NSWVBUT19MSUJfQUVTPXkKQ09ORklHX0NSWVBUT19MSUJfQVJDND1tCkNPTkZJ
R19DUllQVE9fQVJDSF9IQVZFX0xJQl9CTEFLRTJTPXkKQ09ORklHX0NSWVBUT19MSUJfQkxB
S0UyU19HRU5FUklDPXkKQ09ORklHX0NSWVBUT19MSUJfQkxBS0UyUz1tCkNPTkZJR19DUllQ
VE9fQVJDSF9IQVZFX0xJQl9DSEFDSEE9eQpDT05GSUdfQ1JZUFRPX0xJQl9DSEFDSEFfR0VO
RVJJQz15CiMgQ09ORklHX0NSWVBUT19MSUJfQ0hBQ0hBIGlzIG5vdCBzZXQKIyBDT05GSUdf
Q1JZUFRPX0xJQl9DVVJWRTI1NTE5IGlzIG5vdCBzZXQKQ09ORklHX0NSWVBUT19MSUJfREVT
PXkKQ09ORklHX0NSWVBUT19MSUJfUE9MWTEzMDVfUlNJWkU9NApDT05GSUdfQ1JZUFRPX0FS
Q0hfSEFWRV9MSUJfUE9MWTEzMDU9eQpDT05GSUdfQ1JZUFRPX0xJQl9QT0xZMTMwNV9HRU5F
UklDPXkKQ09ORklHX0NSWVBUT19MSUJfUE9MWTEzMDU9bQojIENPTkZJR19DUllQVE9fTElC
X0NIQUNIQTIwUE9MWTEzMDUgaXMgbm90IHNldApDT05GSUdfQ1JZUFRPX0xJQl9TSEEyNTY9
eQpDT05GSUdfQ1JZUFRPX0hXPXkKQ09ORklHX0NSWVBUT19ERVZfUEFETE9DSz15CkNPTkZJ
R19DUllQVE9fREVWX1BBRExPQ0tfQUVTPXkKIyBDT05GSUdfQ1JZUFRPX0RFVl9QQURMT0NL
X1NIQSBpcyBub3Qgc2V0CiMgQ09ORklHX0NSWVBUT19ERVZfQVRNRUxfRUNDIGlzIG5vdCBz
ZXQKIyBDT05GSUdfQ1JZUFRPX0RFVl9BVE1FTF9TSEEyMDRBIGlzIG5vdCBzZXQKQ09ORklH
X0NSWVBUT19ERVZfVklSVElPPXkKIyBDT05GSUdfQ1JZUFRPX0RFVl9BTUxPR0lDX0dYTCBp
cyBub3Qgc2V0CiMgQ09ORklHX0FTWU1NRVRSSUNfS0VZX1RZUEUgaXMgbm90IHNldAoKIwoj
IENlcnRpZmljYXRlcyBmb3Igc2lnbmF0dXJlIGNoZWNraW5nCiMKIyBDT05GSUdfU1lTVEVN
X0JMQUNLTElTVF9LRVlSSU5HIGlzIG5vdCBzZXQKIyBlbmQgb2YgQ2VydGlmaWNhdGVzIGZv
ciBzaWduYXR1cmUgY2hlY2tpbmcKCkNPTkZJR19CSU5BUllfUFJJTlRGPXkKCiMKIyBMaWJy
YXJ5IHJvdXRpbmVzCiMKIyBDT05GSUdfUEFDS0lORyBpcyBub3Qgc2V0CkNPTkZJR19CSVRS
RVZFUlNFPXkKQ09ORklHX0dFTkVSSUNfU1RSTkNQWV9GUk9NX1VTRVI9eQpDT05GSUdfR0VO
RVJJQ19TVFJOTEVOX1VTRVI9eQpDT05GSUdfR0VORVJJQ19GSU5EX0ZJUlNUX0JJVD15CiMg
Q09ORklHX0NPUkRJQyBpcyBub3Qgc2V0CkNPTkZJR19QUklNRV9OVU1CRVJTPW0KQ09ORklH
X0dFTkVSSUNfUENJX0lPTUFQPXkKQ09ORklHX0dFTkVSSUNfSU9NQVA9eQpDT05GSUdfQVJD
SF9VU0VfQ01QWENIR19MT0NLUkVGPXkKQ09ORklHX0FSQ0hfSEFTX0ZBU1RfTVVMVElQTElF
Uj15CiMgQ09ORklHX0NSQ19DQ0lUVCBpcyBub3Qgc2V0CkNPTkZJR19DUkMxNj1tCkNPTkZJ
R19DUkNfVDEwRElGPW0KIyBDT05GSUdfQ1JDX0lUVV9UIGlzIG5vdCBzZXQKQ09ORklHX0NS
QzMyPXkKQ09ORklHX0NSQzMyX1NFTEZURVNUPW0KQ09ORklHX0NSQzMyX1NMSUNFQlk4PXkK
IyBDT05GSUdfQ1JDMzJfU0xJQ0VCWTQgaXMgbm90IHNldAojIENPTkZJR19DUkMzMl9TQVJX
QVRFIGlzIG5vdCBzZXQKIyBDT05GSUdfQ1JDMzJfQklUIGlzIG5vdCBzZXQKQ09ORklHX0NS
QzY0PW0KIyBDT05GSUdfQ1JDNCBpcyBub3Qgc2V0CiMgQ09ORklHX0NSQzcgaXMgbm90IHNl
dApDT05GSUdfTElCQ1JDMzJDPXkKQ09ORklHX0NSQzg9eQpDT05GSUdfWFhIQVNIPW0KIyBD
T05GSUdfUkFORE9NMzJfU0VMRlRFU1QgaXMgbm90IHNldApDT05GSUdfODQyX0NPTVBSRVNT
PW0KQ09ORklHXzg0Ml9ERUNPTVBSRVNTPW0KQ09ORklHX1pMSUJfSU5GTEFURT15CkNPTkZJ
R19aTElCX0RFRkxBVEU9bQpDT05GSUdfTFpPX0RFQ09NUFJFU1M9eQpDT05GSUdfTFo0SENf
Q09NUFJFU1M9bQpDT05GSUdfTFo0X0RFQ09NUFJFU1M9bQpDT05GSUdfWFpfREVDPXkKIyBD
T05GSUdfWFpfREVDX1g4NiBpcyBub3Qgc2V0CiMgQ09ORklHX1haX0RFQ19QT1dFUlBDIGlz
IG5vdCBzZXQKQ09ORklHX1haX0RFQ19JQTY0PXkKIyBDT05GSUdfWFpfREVDX0FSTSBpcyBu
b3Qgc2V0CkNPTkZJR19YWl9ERUNfQVJNVEhVTUI9eQpDT05GSUdfWFpfREVDX1NQQVJDPXkK
Q09ORklHX1haX0RFQ19CQ0o9eQpDT05GSUdfWFpfREVDX1RFU1Q9bQpDT05GSUdfREVDT01Q
UkVTU19HWklQPXkKQ09ORklHX0RFQ09NUFJFU1NfWFo9eQpDT05GSUdfREVDT01QUkVTU19M
Wk89eQpDT05GSUdfR0VORVJJQ19BTExPQ0FUT1I9eQpDT05GSUdfSU5URVJWQUxfVFJFRT15
CkNPTkZJR19BU1NPQ0lBVElWRV9BUlJBWT15CkNPTkZJR19IQVNfSU9NRU09eQpDT05GSUdf
SEFTX0lPUE9SVF9NQVA9eQpDT05GSUdfSEFTX0RNQT15CkNPTkZJR19ORUVEX1NHX0RNQV9M
RU5HVEg9eQpDT05GSUdfTkVFRF9ETUFfTUFQX1NUQVRFPXkKQ09ORklHX0FSQ0hfRE1BX0FE
RFJfVF82NEJJVD15CkNPTkZJR19TV0lPVExCPXkKQ09ORklHX0RNQV9DTUE9eQoKIwojIERl
ZmF1bHQgY29udGlndW91cyBtZW1vcnkgYXJlYSBzaXplOgojCkNPTkZJR19DTUFfU0laRV9N
QllURVM9MApDT05GSUdfQ01BX1NJWkVfUEVSQ0VOVEFHRT0wCiMgQ09ORklHX0NNQV9TSVpF
X1NFTF9NQllURVMgaXMgbm90IHNldAojIENPTkZJR19DTUFfU0laRV9TRUxfUEVSQ0VOVEFH
RSBpcyBub3Qgc2V0CkNPTkZJR19DTUFfU0laRV9TRUxfTUlOPXkKIyBDT05GSUdfQ01BX1NJ
WkVfU0VMX01BWCBpcyBub3Qgc2V0CkNPTkZJR19DTUFfQUxJR05NRU5UPTgKIyBDT05GSUdf
RE1BX0FQSV9ERUJVRyBpcyBub3Qgc2V0CkNPTkZJR19TR0xfQUxMT0M9eQpDT05GSUdfQ1BV
TUFTS19PRkZTVEFDSz15CkNPTkZJR19HTE9CPXkKIyBDT05GSUdfR0xPQl9TRUxGVEVTVCBp
cyBub3Qgc2V0CkNPTkZJR19DTFpfVEFCPXkKIyBDT05GSUdfSVJRX1BPTEwgaXMgbm90IHNl
dApDT05GSUdfTVBJTElCPXkKQ09ORklHX09JRF9SRUdJU1RSWT1tCkNPTkZJR19IQVZFX0dF
TkVSSUNfVkRTTz15CkNPTkZJR19HRU5FUklDX0dFVFRJTUVPRkRBWT15CkNPTkZJR19BUkNI
X0hBU19QTUVNX0FQST15CkNPTkZJR19BUkNIX0hBU19VQUNDRVNTX0ZMVVNIQ0FDSEU9eQpD
T05GSUdfQVJDSF9TVEFDS1dBTEs9eQpDT05GSUdfU1RBQ0tERVBPVD15CkNPTkZJR19TVFJJ
TkdfU0VMRlRFU1Q9eQojIGVuZCBvZiBMaWJyYXJ5IHJvdXRpbmVzCgojCiMgS2VybmVsIGhh
Y2tpbmcKIwoKIwojIHByaW50ayBhbmQgZG1lc2cgb3B0aW9ucwojCiMgQ09ORklHX1BSSU5U
S19USU1FIGlzIG5vdCBzZXQKQ09ORklHX1BSSU5US19DQUxMRVI9eQpDT05GSUdfQ09OU09M
RV9MT0dMRVZFTF9ERUZBVUxUPTcKQ09ORklHX0NPTlNPTEVfTE9HTEVWRUxfUVVJRVQ9NApD
T05GSUdfTUVTU0FHRV9MT0dMRVZFTF9ERUZBVUxUPTQKQ09ORklHX0JPT1RfUFJJTlRLX0RF
TEFZPXkKIyBDT05GSUdfRFlOQU1JQ19ERUJVRyBpcyBub3Qgc2V0CiMgQ09ORklHX1NZTUJP
TElDX0VSUk5BTUUgaXMgbm90IHNldAojIENPTkZJR19ERUJVR19CVUdWRVJCT1NFIGlzIG5v
dCBzZXQKIyBlbmQgb2YgcHJpbnRrIGFuZCBkbWVzZyBvcHRpb25zCgojCiMgQ29tcGlsZS10
aW1lIGNoZWNrcyBhbmQgY29tcGlsZXIgb3B0aW9ucwojCiMgQ09ORklHX0RFQlVHX0lORk8g
aXMgbm90IHNldApDT05GSUdfRU5BQkxFX01VU1RfQ0hFQ0s9eQpDT05GSUdfRlJBTUVfV0FS
Tj0yMDQ4CiMgQ09ORklHX1NUUklQX0FTTV9TWU1TIGlzIG5vdCBzZXQKIyBDT05GSUdfUkVB
REFCTEVfQVNNIGlzIG5vdCBzZXQKQ09ORklHX0hFQURFUlNfSU5TVEFMTD15CkNPTkZJR19P
UFRJTUlaRV9JTkxJTklORz15CiMgQ09ORklHX0RFQlVHX1NFQ1RJT05fTUlTTUFUQ0ggaXMg
bm90IHNldAojIENPTkZJR19TRUNUSU9OX01JU01BVENIX1dBUk5fT05MWSBpcyBub3Qgc2V0
CkNPTkZJR19GUkFNRV9QT0lOVEVSPXkKIyBDT05GSUdfU1RBQ0tfVkFMSURBVElPTiBpcyBu
b3Qgc2V0CkNPTkZJR19ERUJVR19GT1JDRV9XRUFLX1BFUl9DUFU9eQojIGVuZCBvZiBDb21w
aWxlLXRpbWUgY2hlY2tzIGFuZCBjb21waWxlciBvcHRpb25zCgojCiMgR2VuZXJpYyBLZXJu
ZWwgRGVidWdnaW5nIEluc3RydW1lbnRzCiMKQ09ORklHX01BR0lDX1NZU1JRPXkKQ09ORklH
X01BR0lDX1NZU1JRX0RFRkFVTFRfRU5BQkxFPTB4MQojIENPTkZJR19NQUdJQ19TWVNSUV9T
RVJJQUwgaXMgbm90IHNldApDT05GSUdfREVCVUdfRlM9eQpDT05GSUdfSEFWRV9BUkNIX0tH
REI9eQojIENPTkZJR19LR0RCIGlzIG5vdCBzZXQKQ09ORklHX0FSQ0hfSEFTX1VCU0FOX1NB
TklUSVpFX0FMTD15CkNPTkZJR19VQlNBTj15CkNPTkZJR19VQlNBTl9TQU5JVElaRV9BTEw9
eQpDT05GSUdfVUJTQU5fTk9fQUxJR05NRU5UPXkKQ09ORklHX1RFU1RfVUJTQU49bQpDT05G
SUdfSEFWRV9BUkNIX0tDU0FOPXkKQ09ORklHX0tDU0FOPXkKQ09ORklHX0tDU0FOX0RFQlVH
PXkKQ09ORklHX0tDU0FOX1NFTEZURVNUPXkKIyBDT05GSUdfS0NTQU5fRUFSTFlfRU5BQkxF
IGlzIG5vdCBzZXQKQ09ORklHX0tDU0FOX05VTV9XQVRDSFBPSU5UUz02NApDT05GSUdfS0NT
QU5fVURFTEFZX1RBU0s9ODAKQ09ORklHX0tDU0FOX1VERUxBWV9JTlRFUlJVUFQ9MjAKIyBD
T05GSUdfS0NTQU5fREVMQVlfUkFORE9NSVpFIGlzIG5vdCBzZXQKQ09ORklHX0tDU0FOX1NL
SVBfV0FUQ0g9NDAwMAojIENPTkZJR19LQ1NBTl9TS0lQX1dBVENIX1JBTkRPTUlaRSBpcyBu
b3Qgc2V0CiMgQ09ORklHX0tDU0FOX1JFUE9SVF9SQUNFX1VOS05PV05fT1JJR0lOIGlzIG5v
dCBzZXQKQ09ORklHX0tDU0FOX1JFUE9SVF9WQUxVRV9DSEFOR0VfT05MWT15CiMgQ09ORklH
X0tDU0FOX0lHTk9SRV9BVE9NSUNTIGlzIG5vdCBzZXQKIyBlbmQgb2YgR2VuZXJpYyBLZXJu
ZWwgRGVidWdnaW5nIEluc3RydW1lbnRzCgpDT05GSUdfREVCVUdfS0VSTkVMPXkKQ09ORklH
X0RFQlVHX01JU0M9eQoKIwojIE1lbW9yeSBEZWJ1Z2dpbmcKIwpDT05GSUdfUEFHRV9FWFRF
TlNJT049eQojIENPTkZJR19ERUJVR19QQUdFQUxMT0MgaXMgbm90IHNldApDT05GSUdfUEFH
RV9PV05FUj15CkNPTkZJR19QQUdFX1BPSVNPTklORz15CiMgQ09ORklHX1BBR0VfUE9JU09O
SU5HX05PX1NBTklUWSBpcyBub3Qgc2V0CkNPTkZJR19QQUdFX1BPSVNPTklOR19aRVJPPXkK
Q09ORklHX0RFQlVHX1BBR0VfUkVGPXkKIyBDT05GSUdfREVCVUdfUk9EQVRBX1RFU1QgaXMg
bm90IHNldApDT05GSUdfR0VORVJJQ19QVERVTVA9eQpDT05GSUdfUFREVU1QX0NPUkU9eQpD
T05GSUdfUFREVU1QX0RFQlVHRlM9eQpDT05GSUdfREVCVUdfT0JKRUNUUz15CkNPTkZJR19E
RUJVR19PQkpFQ1RTX1NFTEZURVNUPXkKQ09ORklHX0RFQlVHX09CSkVDVFNfRlJFRT15CkNP
TkZJR19ERUJVR19PQkpFQ1RTX1RJTUVSUz15CkNPTkZJR19ERUJVR19PQkpFQ1RTX1dPUks9
eQojIENPTkZJR19ERUJVR19PQkpFQ1RTX1JDVV9IRUFEIGlzIG5vdCBzZXQKQ09ORklHX0RF
QlVHX09CSkVDVFNfUEVSQ1BVX0NPVU5URVI9eQpDT05GSUdfREVCVUdfT0JKRUNUU19FTkFC
TEVfREVGQVVMVD0xCkNPTkZJR19ERUJVR19TTEFCPXkKQ09ORklHX0hBVkVfREVCVUdfS01F
TUxFQUs9eQpDT05GSUdfREVCVUdfS01FTUxFQUs9eQpDT05GSUdfREVCVUdfS01FTUxFQUtf
TUVNX1BPT0xfU0laRT0xNjAwMApDT05GSUdfREVCVUdfS01FTUxFQUtfVEVTVD1tCkNPTkZJ
R19ERUJVR19LTUVNTEVBS19ERUZBVUxUX09GRj15CkNPTkZJR19ERUJVR19LTUVNTEVBS19B
VVRPX1NDQU49eQpDT05GSUdfREVCVUdfU1RBQ0tfVVNBR0U9eQpDT05GSUdfU0NIRURfU1RB
Q0tfRU5EX0NIRUNLPXkKIyBDT05GSUdfREVCVUdfVk0gaXMgbm90IHNldApDT05GSUdfQVJD
SF9IQVNfREVCVUdfVklSVFVBTD15CkNPTkZJR19ERUJVR19WSVJUVUFMPXkKQ09ORklHX0RF
QlVHX01FTU9SWV9JTklUPXkKQ09ORklHX0RFQlVHX1BFUl9DUFVfTUFQUz15CkNPTkZJR19I
QVZFX0FSQ0hfS0FTQU49eQpDT05GSUdfSEFWRV9BUkNIX0tBU0FOX1ZNQUxMT0M9eQpDT05G
SUdfQ0NfSEFTX0tBU0FOX0dFTkVSSUM9eQpDT05GSUdfS0FTQU5fU1RBQ0s9MQojIGVuZCBv
ZiBNZW1vcnkgRGVidWdnaW5nCgojIENPTkZJR19ERUJVR19TSElSUSBpcyBub3Qgc2V0Cgoj
CiMgRGVidWcgT29wcywgTG9ja3VwcyBhbmQgSGFuZ3MKIwpDT05GSUdfUEFOSUNfT05fT09Q
Uz15CkNPTkZJR19QQU5JQ19PTl9PT1BTX1ZBTFVFPTEKQ09ORklHX1BBTklDX1RJTUVPVVQ9
MAojIENPTkZJR19TT0ZUTE9DS1VQX0RFVEVDVE9SIGlzIG5vdCBzZXQKQ09ORklHX0hBUkRM
T0NLVVBfQ0hFQ0tfVElNRVNUQU1QPXkKIyBDT05GSUdfSEFSRExPQ0tVUF9ERVRFQ1RPUiBp
cyBub3Qgc2V0CkNPTkZJR19ERVRFQ1RfSFVOR19UQVNLPXkKQ09ORklHX0RFRkFVTFRfSFVO
R19UQVNLX1RJTUVPVVQ9MTIwCiMgQ09ORklHX0JPT1RQQVJBTV9IVU5HX1RBU0tfUEFOSUMg
aXMgbm90IHNldApDT05GSUdfQk9PVFBBUkFNX0hVTkdfVEFTS19QQU5JQ19WQUxVRT0wCiMg
Q09ORklHX1dRX1dBVENIRE9HIGlzIG5vdCBzZXQKIyBlbmQgb2YgRGVidWcgT29wcywgTG9j
a3VwcyBhbmQgSGFuZ3MKCiMKIyBTY2hlZHVsZXIgRGVidWdnaW5nCiMKIyBlbmQgb2YgU2No
ZWR1bGVyIERlYnVnZ2luZwoKQ09ORklHX0RFQlVHX1RJTUVLRUVQSU5HPXkKCiMKIyBMb2Nr
IERlYnVnZ2luZyAoc3BpbmxvY2tzLCBtdXRleGVzLCBldGMuLi4pCiMKQ09ORklHX0xPQ0tf
REVCVUdHSU5HX1NVUFBPUlQ9eQpDT05GSUdfUFJPVkVfTE9DS0lORz15CkNPTkZJR19MT0NL
X1NUQVQ9eQpDT05GSUdfREVCVUdfUlRfTVVURVhFUz15CkNPTkZJR19ERUJVR19TUElOTE9D
Sz15CkNPTkZJR19ERUJVR19NVVRFWEVTPXkKQ09ORklHX0RFQlVHX1dXX01VVEVYX1NMT1dQ
QVRIPXkKQ09ORklHX0RFQlVHX1JXU0VNUz15CkNPTkZJR19ERUJVR19MT0NLX0FMTE9DPXkK
Q09ORklHX0xPQ0tERVA9eQpDT05GSUdfREVCVUdfTE9DS0RFUD15CiMgQ09ORklHX0RFQlVH
X0FUT01JQ19TTEVFUCBpcyBub3Qgc2V0CiMgQ09ORklHX0RFQlVHX0xPQ0tJTkdfQVBJX1NF
TEZURVNUUyBpcyBub3Qgc2V0CiMgQ09ORklHX0xPQ0tfVE9SVFVSRV9URVNUIGlzIG5vdCBz
ZXQKQ09ORklHX1dXX01VVEVYX1NFTEZURVNUPXkKIyBlbmQgb2YgTG9jayBEZWJ1Z2dpbmcg
KHNwaW5sb2NrcywgbXV0ZXhlcywgZXRjLi4uKQoKQ09ORklHX1RSQUNFX0lSUUZMQUdTPXkK
Q09ORklHX1NUQUNLVFJBQ0U9eQpDT05GSUdfV0FSTl9BTExfVU5TRUVERURfUkFORE9NPXkK
IyBDT05GSUdfREVCVUdfS09CSkVDVCBpcyBub3Qgc2V0CiMgQ09ORklHX0RFQlVHX0tPQkpF
Q1RfUkVMRUFTRSBpcyBub3Qgc2V0CgojCiMgRGVidWcga2VybmVsIGRhdGEgc3RydWN0dXJl
cwojCkNPTkZJR19ERUJVR19MSVNUPXkKIyBDT05GSUdfREVCVUdfUExJU1QgaXMgbm90IHNl
dAojIENPTkZJR19ERUJVR19TRyBpcyBub3Qgc2V0CkNPTkZJR19ERUJVR19OT1RJRklFUlM9
eQojIENPTkZJR19CVUdfT05fREFUQV9DT1JSVVBUSU9OIGlzIG5vdCBzZXQKIyBlbmQgb2Yg
RGVidWcga2VybmVsIGRhdGEgc3RydWN0dXJlcwoKQ09ORklHX0RFQlVHX0NSRURFTlRJQUxT
PXkKCiMKIyBSQ1UgRGVidWdnaW5nCiMKQ09ORklHX1BST1ZFX1JDVT15CkNPTkZJR19QUk9W
RV9SQ1VfTElTVD15CkNPTkZJR19UT1JUVVJFX1RFU1Q9eQpDT05GSUdfUkNVX1BFUkZfVEVT
VD15CkNPTkZJR19SQ1VfVE9SVFVSRV9URVNUPW0KQ09ORklHX1JDVV9DUFVfU1RBTExfVElN
RU9VVD0yMQpDT05GSUdfUkNVX1RSQUNFPXkKIyBDT05GSUdfUkNVX0VRU19ERUJVRyBpcyBu
b3Qgc2V0CiMgZW5kIG9mIFJDVSBEZWJ1Z2dpbmcKCiMgQ09ORklHX0RFQlVHX1dRX0ZPUkNF
X1JSX0NQVSBpcyBub3Qgc2V0CiMgQ09ORklHX0NQVV9IT1RQTFVHX1NUQVRFX0NPTlRST0wg
aXMgbm90IHNldApDT05GSUdfVVNFUl9TVEFDS1RSQUNFX1NVUFBPUlQ9eQpDT05GSUdfTk9Q
X1RSQUNFUj15CkNPTkZJR19IQVZFX0ZVTkNUSU9OX1RSQUNFUj15CkNPTkZJR19IQVZFX0ZV
TkNUSU9OX0dSQVBIX1RSQUNFUj15CkNPTkZJR19IQVZFX0RZTkFNSUNfRlRSQUNFPXkKQ09O
RklHX0hBVkVfRFlOQU1JQ19GVFJBQ0VfV0lUSF9SRUdTPXkKQ09ORklHX0hBVkVfRFlOQU1J
Q19GVFJBQ0VfV0lUSF9ESVJFQ1RfQ0FMTFM9eQpDT05GSUdfSEFWRV9GVFJBQ0VfTUNPVU5U
X1JFQ09SRD15CkNPTkZJR19IQVZFX1NZU0NBTExfVFJBQ0VQT0lOVFM9eQpDT05GSUdfSEFW
RV9GRU5UUlk9eQpDT05GSUdfSEFWRV9DX1JFQ09SRE1DT1VOVD15CkNPTkZJR19UUkFDRV9D
TE9DSz15CkNPTkZJR19SSU5HX0JVRkZFUj15CkNPTkZJR19FVkVOVF9UUkFDSU5HPXkKQ09O
RklHX0NPTlRFWFRfU1dJVENIX1RSQUNFUj15CkNPTkZJR19QUkVFTVBUSVJRX1RSQUNFUE9J
TlRTPXkKQ09ORklHX1RSQUNJTkc9eQpDT05GSUdfVFJBQ0lOR19TVVBQT1JUPXkKIyBDT05G
SUdfRlRSQUNFIGlzIG5vdCBzZXQKQ09ORklHX0tVTklUPXkKQ09ORklHX0tVTklUX1RFU1Q9
eQpDT05GSUdfS1VOSVRfRVhBTVBMRV9URVNUPXkKQ09ORklHX1NBTVBMRVM9eQpDT05GSUdf
U0FNUExFX1RSQUNFX0VWRU5UUz1tCkNPTkZJR19TQU1QTEVfVFJBQ0VfUFJJTlRLPW0KQ09O
RklHX1NBTVBMRV9LT0JKRUNUPXkKQ09ORklHX1NBTVBMRV9LUFJPQkVTPW0KIyBDT05GSUdf
U0FNUExFX0tSRVRQUk9CRVMgaXMgbm90IHNldAojIENPTkZJR19TQU1QTEVfSFdfQlJFQUtQ
T0lOVCBpcyBub3Qgc2V0CkNPTkZJR19TQU1QTEVfS0ZJRk89bQpDT05GSUdfU0FNUExFX1JQ
TVNHX0NMSUVOVD1tCkNPTkZJR19TQU1QTEVfQ09ORklHRlM9bQpDT05GSUdfU0FNUExFX0hJ
RFJBVz15CkNPTkZJR19TQU1QTEVfUElERkQ9eQojIENPTkZJR19TQU1QTEVfVkZTIGlzIG5v
dCBzZXQKIyBDT05GSUdfU0FNUExFX1dBVENIX1FVRVVFIGlzIG5vdCBzZXQKQ09ORklHX0FS
Q0hfSEFTX0RFVk1FTV9JU19BTExPV0VEPXkKIyBDT05GSUdfREVCVUdfQUlEX0ZPUl9TWVpC
T1QgaXMgbm90IHNldAoKIwojIHg4NiBEZWJ1Z2dpbmcKIwpDT05GSUdfVFJBQ0VfSVJRRkxB
R1NfU1VQUE9SVD15CkNPTkZJR19YODZfVkVSQk9TRV9CT09UVVA9eQpDT05GSUdfRUFSTFlf
UFJJTlRLPXkKQ09ORklHX0RFQlVHX1dYPXkKIyBDT05GSUdfRE9VQkxFRkFVTFQgaXMgbm90
IHNldApDT05GSUdfREVCVUdfVExCRkxVU0g9eQpDT05GSUdfSEFWRV9NTUlPVFJBQ0VfU1VQ
UE9SVD15CkNPTkZJR19YODZfREVDT0RFUl9TRUxGVEVTVD15CkNPTkZJR19JT19ERUxBWV8w
WDgwPXkKIyBDT05GSUdfSU9fREVMQVlfMFhFRCBpcyBub3Qgc2V0CiMgQ09ORklHX0lPX0RF
TEFZX1VERUxBWSBpcyBub3Qgc2V0CiMgQ09ORklHX0lPX0RFTEFZX05PTkUgaXMgbm90IHNl
dAojIENPTkZJR19ERUJVR19CT09UX1BBUkFNUyBpcyBub3Qgc2V0CiMgQ09ORklHX0NQQV9E
RUJVRyBpcyBub3Qgc2V0CkNPTkZJR19ERUJVR19FTlRSWT15CkNPTkZJR19ERUJVR19OTUlf
U0VMRlRFU1Q9eQpDT05GSUdfWDg2X0RFQlVHX0ZQVT15CiMgQ09ORklHX1VOV0lOREVSX09S
QyBpcyBub3Qgc2V0CkNPTkZJR19VTldJTkRFUl9GUkFNRV9QT0lOVEVSPXkKIyBlbmQgb2Yg
eDg2IERlYnVnZ2luZwoKIwojIEtlcm5lbCBUZXN0aW5nIGFuZCBDb3ZlcmFnZQojCkNPTkZJ
R19BUkNIX0hBU19LQ09WPXkKQ09ORklHX0NDX0hBU19TQU5DT1ZfVFJBQ0VfUEM9eQpDT05G
SUdfS0NPVj15CiMgQ09ORklHX0tDT1ZfSU5TVFJVTUVOVF9BTEwgaXMgbm90IHNldApDT05G
SUdfUlVOVElNRV9URVNUSU5HX01FTlU9eQpDT05GSUdfTEtEVE09bQpDT05GSUdfVEVTVF9M
SVNUX1NPUlQ9bQojIENPTkZJR19URVNUX1NPUlQgaXMgbm90IHNldApDT05GSUdfS1BST0JF
U19TQU5JVFlfVEVTVD15CkNPTkZJR19CQUNLVFJBQ0VfU0VMRl9URVNUPW0KIyBDT05GSUdf
UkJUUkVFX1RFU1QgaXMgbm90IHNldAojIENPTkZJR19SRUVEX1NPTE9NT05fVEVTVCBpcyBu
b3Qgc2V0CkNPTkZJR19JTlRFUlZBTF9UUkVFX1RFU1Q9bQojIENPTkZJR19QRVJDUFVfVEVT
VCBpcyBub3Qgc2V0CkNPTkZJR19BVE9NSUM2NF9TRUxGVEVTVD1tCkNPTkZJR19URVNUX0hF
WERVTVA9eQpDT05GSUdfVEVTVF9TVFJJTkdfSEVMUEVSUz15CiMgQ09ORklHX1RFU1RfU1RS
U0NQWSBpcyBub3Qgc2V0CiMgQ09ORklHX1RFU1RfS1NUUlRPWCBpcyBub3Qgc2V0CiMgQ09O
RklHX1RFU1RfUFJJTlRGIGlzIG5vdCBzZXQKQ09ORklHX1RFU1RfQklUTUFQPXkKIyBDT05G
SUdfVEVTVF9CSVRGSUVMRCBpcyBub3Qgc2V0CkNPTkZJR19URVNUX1VVSUQ9eQojIENPTkZJ
R19URVNUX1hBUlJBWSBpcyBub3Qgc2V0CkNPTkZJR19URVNUX09WRVJGTE9XPW0KIyBDT05G
SUdfVEVTVF9SSEFTSFRBQkxFIGlzIG5vdCBzZXQKQ09ORklHX1RFU1RfSEFTSD15CkNPTkZJ
R19URVNUX0lEQT1tCkNPTkZJR19URVNUX0xLTT1tCkNPTkZJR19URVNUX1ZNQUxMT0M9bQpD
T05GSUdfVEVTVF9VU0VSX0NPUFk9bQojIENPTkZJR19GSU5EX0JJVF9CRU5DSE1BUksgaXMg
bm90IHNldApDT05GSUdfVEVTVF9GSVJNV0FSRT15CiMgQ09ORklHX1NZU0NUTF9LVU5JVF9U
RVNUIGlzIG5vdCBzZXQKIyBDT05GSUdfTElTVF9LVU5JVF9URVNUIGlzIG5vdCBzZXQKQ09O
RklHX1RFU1RfVURFTEFZPW0KQ09ORklHX1RFU1RfU1RBVElDX0tFWVM9bQojIENPTkZJR19U
RVNUX0RFQlVHX1ZJUlRVQUwgaXMgbm90IHNldApDT05GSUdfVEVTVF9NRU1DQVRfUD1tCkNP
TkZJR19URVNUX1NUQUNLSU5JVD1tCkNPTkZJR19URVNUX01FTUlOSVQ9eQojIENPTkZJR19N
RU1URVNUIGlzIG5vdCBzZXQKIyBDT05GSUdfTk9USUZJRVJfRVJST1JfSU5KRUNUSU9OIGlz
IG5vdCBzZXQKQ09ORklHX0ZVTkNUSU9OX0VSUk9SX0lOSkVDVElPTj15CkNPTkZJR19GQVVM
VF9JTkpFQ1RJT049eQojIENPTkZJR19GQUlMU0xBQiBpcyBub3Qgc2V0CiMgQ09ORklHX0ZB
SUxfUEFHRV9BTExPQyBpcyBub3Qgc2V0CiMgQ09ORklHX0ZBSUxfRlVURVggaXMgbm90IHNl
dApDT05GSUdfRkFVTFRfSU5KRUNUSU9OX0RFQlVHX0ZTPXkKIyBDT05GSUdfRkFJTF9GVU5D
VElPTiBpcyBub3Qgc2V0CiMgZW5kIG9mIEtlcm5lbCBUZXN0aW5nIGFuZCBDb3ZlcmFnZQoj
IGVuZCBvZiBLZXJuZWwgaGFja2luZwo=
--------------C7218DDDD46B2547AEB41C50--
